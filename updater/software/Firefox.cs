﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/140.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f1d0581fe5c4751aead6902c47a73bad0792950d8b7f6053b24317680f53f73888c48b29fac00235c2eb2a3514e2f1f67bc2e5c4bbb92e929c26cab756daaaf0" },
                { "af", "07fa330bdebf0e3533157c424763404fa9b62c6618daf27cbde00e8904ca6dd811ab2d1b96614637853e9e572d2334144524053dfc23348007cca14a689e61c3" },
                { "an", "d24c274e0c7ff2c0d57e99fbc09b21ea290b616e3765b1c5cb2e0e9b17f72eaa124572d5264dcc3bf1c1f63cd4bade76dac37ee7dcc3f172cb05de627952445e" },
                { "ar", "c3d1994a9bed4693a0233c901c6e0c775b3040841d231ef01037b60698a079a920d9386785ef3566b08840a5ca5f6f0a7b0303518747dfd4a6fe3a73a4fb3dae" },
                { "ast", "b68eb0aeac32e2e5a812ec77b513352ec65cf3d03c01277974106f8ba8ca7e98dd9b3f8d593ffe0ffb453f0500c406e32a6743f8205762b521f2ef612fee675e" },
                { "az", "54bca0082f32e8368a8dd9f698e56233f111ea6eb27654bf81956fffdb4f344fc6fe5de0427ed53df97e6523dd34824f4ae8e7580535daeb14855eff33b9a602" },
                { "be", "5c804c79d6adc53b866c0983f9a7b864c1b30cea67337528b27e6a256eec7ac9153f4ca79db68a9fc2f5b788646b88db6de1a6fdbcb1aac0f09e059681d0756d" },
                { "bg", "a156fe396266434a373f89f6995633f45d2b9b43eaa36f7f563717b8bd643f80cfe0de2e79ab4e6b222de52e437b676a8279d18e8aede4ae6be47f456cdb5b47" },
                { "bn", "9b39b485c4a44f6a5ff3203351d97fd6708a39d5c1a65d07c71f7ed95dddb96ade0e057c50507ee1fcf4d15773d9667fa85a0a94474b47da75f220a2cb1c3d27" },
                { "br", "901463f7743b57aaab7d14603c0a5eaa80411b54ea271b9a8d32126c6d2d219d2e075b2880fe7e5f6b7d5ea8cf1d16ab95161e411b9e75a818a7255272a9ae0d" },
                { "bs", "6fefb13b8b24ba0d236add37bf9394e39faf782e5c3fc10e55fff88374bcb8c5195023aa0053a4dd4ffeb36f86050cdcbe9cd100be3c815c27b5ed9da77b7258" },
                { "ca", "eaded0f909f62848a69c05c08101b516fdde187a8125653a743cc3de2f5222ea5777322e621aaf2ce80a342ff8bd67b8a3764e38d270aa53e8dff7933349061e" },
                { "cak", "7989706c6f1b55b7e8e1ec39c36bd44754c12a8b3aa6dd2ae2a354813767ca4f5e4da39f2ff7a11fe5854e05a2fbbc09208b32db1b33b1d256d0857516ce0ab7" },
                { "cs", "3b2bb3bb6484181e93efe7bb46eee718d635078a37f139dc56fd24a85b18c9f49516aeb1ec26c5c70e5f83cb2b6b265d87b39fbeee05206ff78cbdd57465b7ba" },
                { "cy", "87a71fff16ae90dc721e3a5c3077a80926aa1e7a338a46c00366e847c874a2a589487b962cc757b1cb656005ab5bc50225a5bea981e15e6b621a355329b56b5f" },
                { "da", "f4b9768eada23b26d66af92551634abc981e3d71c98374a1b77a11947df96c9a025eb096855da78872e808b2672c73ef17a2f69a36a2d70736f0ea12b6b0e94b" },
                { "de", "4ec040e1544fb814fc87fe693fe1cd0be160127a3237da55ba8e9d519b369ec3def3004ea50cb29c3f697f1d67cf999d0659eeb82d738401aa3f3d1a8ca27896" },
                { "dsb", "d3e74c4a913b3d44cd470467419af8781cb043943b1268d9c28722552732bd9f98b539e2b88cda3a546dac5ebfc0b377287918ecc9d586953e9fd8200a7972fe" },
                { "el", "d0cf4ded094693de564d1a6c8780335a9d6b9b6f173ec6b7ce904a94d8a00286d45d1d0afab71eeb68f3ddd9a53202cf5467e86541fa10a942caddb793df7e47" },
                { "en-CA", "404040baec5dc7d14b4120d40268236ea4716d5e7a27be2c17e8cda1c90853e424d2aa2c79e21f106e6a5444ef2307b098b69077eef5e4121cb520692a43563a" },
                { "en-GB", "9ab634f0a9fe97dbc687a76ac0a99ccf10ddfb1d75b9658ea51c81840f8d5aabb8c05f5cc30bed40942783eac2edf438d36bca3cfa7de7d1871674eef7d49cf4" },
                { "en-US", "b772b48b4b6f0bac582be3ad318acd67507a8ba07e7b7eb594e07d6920728c931dc806618deec0b28e2a2323df93a2ea80821bb62b8288c0dbf23272e870d781" },
                { "eo", "3899870b76591cd188d57b7984e94b7a60419dfde70ffd616dff2c04afe0ee913ab60782eaf1863f6aa6dc8ec1eeb554466b58a4645a42d99af70f73c596108c" },
                { "es-AR", "8dbea18435947832341ce25dbe97c6c4fa43b2e9796b9038ba8d187eed02311053d88e40f346c0ae69d58feb748ac6eac596a2e97009cb85d27a0f8db7161c88" },
                { "es-CL", "95f4521a4eb251e5298100bbb83fa13250af6ba0316ca052828bf26f001679c4045eb41c3fce1029384f29827e49bb4ab68335ae751857060cf221d2df16c87a" },
                { "es-ES", "7682b8bccb89a4b967d1a0179cc892a462abd9bdd84eeb4c59be7fe1d2bde150ea1f04f4c6dd9da28ae903886f7068adc95f1bf7dbe9410751ffad5a96d43405" },
                { "es-MX", "bb16cb8c6e97b9abbda6f67c7fa1105204c1b18ddc5120590f76ab766bc8a704f408c652bff0466cf0e63d66199200f290876e73873eb9765fa5ae19a4373912" },
                { "et", "3f8e2180cdd432a69a146760027961111b041718cdb4579071ca2ef3be189113b56567e42ab6b396d3986bf6c111bf83c7f7092151f97191cb463e0d94d269f5" },
                { "eu", "0ab4ff4f014b816887a1f54a15b0989a59a4c5e431f1c64121408d535d6ae25af4b86652bac8d1234097756f7368417e5d5beae6a4dca21c0e9e2d81e5b2021b" },
                { "fa", "50c06bf7400b816a877063a10f690e9d07e48f2bb4a84b6cf5ac910c2b5a7241e66dc01fd68daece9c46dd856b8f6a9622f01b74945e590f1c59d5b342070a85" },
                { "ff", "e76967a872bf642ddb7ede3b097d5e4a7f0633bfaec3ddb00ee8994159cab233d35651024cbbdc6bd803244170e791e1e608625993da2c34b4f6e0de598ecde2" },
                { "fi", "1ecc6e32500049deb1d92aa1a1f8f09f9e6f4f3a63810493bfe38b7ebcfe168a1c497194be1776750cc3ea87665da6f52b897f66e6791f73389d8567c85b5a02" },
                { "fr", "660543a28f1f468424ed635177b6e86e44f59d446b20d8bf09b98f4229b8871a094f833ae6f647423347f44177585e45ccb024b4ec331626ffb3c5eea2661cf3" },
                { "fur", "3825099b727636649baf2d4da59e030553982580761048180589806bd0f9b01649a435c5654bcc63925bbf765f183c538fd354a7c2542bb3a3e25ed0efb02338" },
                { "fy-NL", "432d2db104c50b5e53d348098ae9ac1095970968a23656272f8dbf6e510e407aed9b87df28149aa71c73bee8f07288e604402a4700cfc1ded7b8aec0d63d35ff" },
                { "ga-IE", "490bae7494fe1a26d517cb17ae3aec301911bdfe1c928477102c1b93cd0032b72a0698910fe92aa841daca4d582f535a816399d0ba3efd8e6dac34f71d2d01fd" },
                { "gd", "52d730f1df036c362d4d4834a26ced40307969e77058bdaf3439262c30b6013959d0fb600803fe818ec6ce06bf821236e0366c33380ca63f51becaecd607e718" },
                { "gl", "9d14f78d2cd84644e6410ace17acffb6de687d5a2fd26c107bbf62aa00c29ff2951b776d655b06a5e4cbfee2309b69f41da61eeb24d3501a28ad19d0b637f16b" },
                { "gn", "254d95e52eb0c5149ae3cfb5cc4e10f94bf1e3fc43481f9023bcc34c84bb5d46d8c678e88286aee5e8ea0f4744aa7a8b7f42b503de5b450c257733923fa88086" },
                { "gu-IN", "518ab34a8e232f383c8ab3ce4f68f4c3bc21ff3eac3147a4d221dace8294a4730efc55d31ee42cb9c96d696488a4e8dfaeb1131352fcab8370f09c20fc81b158" },
                { "he", "f0647551828a43b9084eb4d062d15dd2fbf2624ac32e7238cde434d8d9be1c889eb5368b240337a6efcbdbf4e44f82ba29131f02f78b13f5c87ec7dff85a8ec1" },
                { "hi-IN", "3f55be1eba3c6ed54e818291e6501afb6872889c71cc4a1b74c96c462484bfe95c60f60116eda2894a0aece041d75b5513941702f809d2aaa2fd67cafc871ff7" },
                { "hr", "e1dac1775edcab8d4de68a1bfa58d0f19ff0601e34781b5cf1920aadeccef92d2d54052fe0e809e8708f41ed72fa95b618202f351a0576d78875ff22d79120a4" },
                { "hsb", "395a8d0857efa22d27ec8f7b8af3eb395eb386dad9c85a0f2e1826ff1e7e1254db4ed6d57bb8ff309da73d3938b3c18ce1b83e822a092f0ba85cdd0511b1ad59" },
                { "hu", "b97eebbe4d1fbe418668532b693b903544d31a273f00e431a822f0c2f222f3aad3c5362e06eb47bc6253c317f47933bd07580d765fbf7a327565a512ddbdf3ee" },
                { "hy-AM", "31b39a72ac39781bf853351cbea33778c7faeb99ff54e10a905cb2276fb7963c343504e6b15bf114a0c3d0da6a409ed41109b14426d8b9fc95c7e42cd7d32a2f" },
                { "ia", "f5b63c656669aaf3815e9da25b8e285c1527551abd5fd64345b8fa0506fed3b7d1034dbeda11f287faadd8788b7dd6044e3c4070651aa8c66636b81052374bee" },
                { "id", "48807cdf07197832ba237587ba4cd043dd89296d185717ae6ebe0ef4e980b679545ab2e6cd52d5139e843d461a68cba70b3298ae9954eb95ffcb5e9c22fe26ab" },
                { "is", "50a20b423576aea243f43349d88bd7f01691dae3f631ed83f7294e362188944787e204910ba73f43b701baae67e2bf9d2669750d62b4f69e8434e95ee9393aca" },
                { "it", "9a978770eeccead783a39875af037b015c41bd5d791ec5925a4d1e931048c8adf2eba87ff5fd90ad266586f9c1cf785035b792edd604bdf4531b49d27616e644" },
                { "ja", "2617f843b9cd6137b8ee296726888a6d84aed752d855335d861fe316b5db8d584aaef1469ce0b1333f4344101f19b65e687cdf00925a5a6e6cf7523127e1c3b5" },
                { "ka", "74d0bae43f3aaaaf219fbb02fe11ce7fb0b67124dd8f88f36bfe3b3d6b51c79db3e5a6b5ff6e2c3865179ee0d06b1072bac2d2e3d9e615160692c895dd066db8" },
                { "kab", "3fe68b0a37757dd4541c9228ca91bdab7f03642c8f7b5ec6614fc3ace4490619534dab8fcbfc8adce4b97b54cd73a6eb56edd08eec4bb6329975b4225b702a0b" },
                { "kk", "9925af07e74b4710c2a10cfe8f01748335b52e6925cdf9727f8ec1206075055098720f00764ba6fba085023f6e59483d68f8b407db9c09bfd6b165ce991c9fef" },
                { "km", "c3a98d5cf44bcb48f3afd2a83773bdb4562fb00d526fe8b8a38909baaf9201c5d4364ed8e523cb3454b554dc66ef83e516c566cd1b0a30f2c526fe4cfdaa3f58" },
                { "kn", "44efca4be1075ebd1c170b3d65552da46ad24db43060ae7d9fbe9d57942fa2913f177468318fd7cdc39945b6bcffc08a25b27f7f070e36f13eda18dc4b051cdd" },
                { "ko", "63c3e6c43e84cee342f16f2a23c5f1899e84bc810492818ee69f1305d6935eb75c80e7aab92576f5563b19e7dca535d1add536d6a54cb4be3cfa2bd24b5455f9" },
                { "lij", "6d24e17b22e8039c835c554564d42ca3bae9bce009eace10640520c75b9577c6da561bc252e4139b22d46c8430e0c6456ad9e91e3e5660b321d70d97cbe6f479" },
                { "lt", "348f599ec163bb73883c72cfd04e697124720e2186e3e513a9e89e7b61a41059887c5b416a614242f64e35e1d711f56e15be7095af7d8374507370709d3e2fcc" },
                { "lv", "1b634e8f34dab7acdb6d3e261b8aacbbe7d95988d8d51e6db31b4c1deadabad844506e5812103e8c24328d7faf0e69b9b76633d66584b26f61d04c9e63a41307" },
                { "mk", "b944f8d57bead5d88e4779e33216e1b673f97ba42000f0a5cc8a79beb3d0191979704eb4976028fdabf6784ffbca22c30becde5904794686c4d5a77fccd31d4e" },
                { "mr", "399fce71d45dfb35ed1e1a5713d8ae4c0193429045e3bf1bcbdf92ff670c800b6f4ac4e0d4033d2fd5fa60200005b089cf0f92cc59db456c71b222976ac71abe" },
                { "ms", "31d21ed10cfc2c15ce46d6ea15c4246df55bd91828c04cfdd35a424a6604d10426dcfd9476869d6804388535b8fa8a73ab5006aa47558c02c31d1f01a09642c0" },
                { "my", "ed7e94911df5ad759ebabf16c6a103dd53143adc18e10169641bb4e0f4faa2c0381ec1b7b0033a2501d3103c2850d469ed27cae759bd2d608570879433be4d88" },
                { "nb-NO", "c1e3e2ee14d4af5847c745709da6aa835e7fa46c4808883d6a4fd6e7245a9745d0053474220725beeab0dd23c39f187b4bfc9f95804309b0cbd8827f6eb1bc6a" },
                { "ne-NP", "cc7ede59b68a058d117aaf23d9daff881b88f1206f5190e40e009d78dbdc7e70665cca542ed94414ca70ce8e952cb31a98e0436ee1177239150a6765c3bc19c8" },
                { "nl", "172b755e0e2ec6063f0c7e2d2396580cf09809b71b8b79a253e5c266064ad452c1a6139ee0f6a12d0719a4c4ee1a2188e66437e7863285d7205e6a57cdc1fc18" },
                { "nn-NO", "b95b6c4c9c951f931f0fe427d90fa35370535e53e396ef131b1f57701da24d262bd48bf43c7a413361d140c91e403d380b184da159b6b23e771fbe5a46bc4108" },
                { "oc", "be384c0ce67e71717e433d2cdb6dfb27c622e205920cb5a68d130d98c3af7333065f5bf2f9ee773d81b42625bb2fcb467f6b079c693faba16ed96e1c9900bc87" },
                { "pa-IN", "3637e7d509a58b4c04536fd7044192a577bfb9c73af0501af4a15ab6812b384e04560fd17a905ebe10d528d3b4fad4dca482b5bcbdde45e1dd6a5342091da8aa" },
                { "pl", "cdec4fb00b59dec120474840345a8790921631e76d72d4e0772e41e7f7e15ee042456061579aa77f588bf45ee528c487a19513861948b3ff83c93ddf0956f1f1" },
                { "pt-BR", "0760e3904db9b064c90f289b43c868c9885c0a9e34bd5d5cf9b87760f1ca69bd7991581d56ca927735d93ffcf53f209e0651030e3a525d45fc5316816c8eb975" },
                { "pt-PT", "b3c1cb30bba196d3d60f8bcf9b3ea77faaa2e543c61499baf52397518ebb5a04ada8bda38e829488dbb8787e7d2577e1eca3512b3d3d341c5d24783767e301ee" },
                { "rm", "9c34e3da756cec0498bcfc6fd7a825121fe5a22c53d651e05d8329a87a0625b2b43a4a423fdfd0092c040485bbc677b9be758e0fa47c88eb7c103d7ec6c837c0" },
                { "ro", "2bf4e016bb449a334d98655a701d6956ce4d4741a6937a895318d5a81668117d6bc1bddcd4ea61cc8bce786f8d572b0f3512b9cb896d1dbf35c63c81ac0cab34" },
                { "ru", "86830358a859f7904af819dd1762e6045700abf6082fc625790fd8b21660d0f3109e2cf80291d68deef8110cc91c346592558d002fa095503215f1332ea79c47" },
                { "sat", "ee4d64f38bef9e1f1e35a6116a63389c21cca79aba9cd7b958b8d9da022a624ec5208dd69f0d0a2576d003b1ef759a27ba968002771e324ab8b546c8dead1f8a" },
                { "sc", "a79293f22b1a0d18891d37a8e6d7da1e3343a61b6dad7dde3d6aef4e77bef0b57a0a3e37c6e9f5d87a286054d8a2604ee5dd9ee3f4d2b51c864e2bb79ff54cbe" },
                { "sco", "bc31f477c1430203c7e466bd9330f4a612a032530eb8540fc8e6a067ed39307f2aee3c1394fbdb6d879b1692803bd9a6275dd56ca8c3d9c20b701ff23acbf2b2" },
                { "si", "75ccb32ad101662e21a95aa5bcd69aeb917f2eb726e0e194d8ae2c9f64fc951ad15f32c33d7b3374c9fd0d7a073d613e62ab8d3bd2409c9b016356a326ef368a" },
                { "sk", "638a38313fa714ad518e2362d94083ed599ca8dd1b217ffca9df3b0babe91daf447b19b431310a2906aedd548e4c465a14d487defcb02d20c76df33201d4562c" },
                { "skr", "00aa414885477b59a1cef72b17f586a213908797c46f653d3df2780825d7f78b2e2cd28fcffbd6aca5aa78dc60b579c4e4ea98cdf6b5cf66ef74d090d624aa9f" },
                { "sl", "50030a185e6ddb39ab50eecb33767e646c5d30ebe79e5f5daf073ad4557a1167f829b9c73dd070022bd5072ef9d5ff7b056d7ed0232893f3565ef3ca57f48c85" },
                { "son", "0e1600e9d78a2d64b1e2fc47fa8e4884eec621b0389605e2d0ca3334fcd3663c7cd1e20b2c3d479892e7c7771c005bf3888c7e6e192a0c6ac6824aca8ebf032a" },
                { "sq", "cb98bb3245b436a274a397130bc4b0247dae5669cab8c5ecd660e40b084ba3aba07fa3ea61094c0a9d8895ba8fa76e0610c8a8135d5028e9e3fcd16bbe15bae8" },
                { "sr", "2faca5350ec3e5b14ec0d751b8a823f36df436381a6d7bd4acb2de21f6fdc922974eb6390721f05bcc3ed623365982e53d90a09e832b76c87047d504fe167ccf" },
                { "sv-SE", "61646aa42cb5b90ccb3e885bbdfe64fe34c9686477612352ebc6b1644176b9948ddbf435c0f4b53b1e6ff8c154924811d4216d174fa943cb2e769b796d6de89c" },
                { "szl", "0dae3ed43d7cebc50a5275a1c8c67a867593c38241044b5dfd2cbcf691d8b408e50af6183906ff3335817c8c1ad39b1e4154215f38f55c2ac2db4ededa08cee9" },
                { "ta", "20ebe8231c133ea6ef0541ec394513d218f8fa22f2cffcd5b6a8392606f85a69392d2920c5c97a9b19fc1a5dd1c52426e1dc0a45d0d22bd692081a08a86a0b55" },
                { "te", "ffff16973979aaaa86d8e0ab33e08ac8f53a7611af8f88a2af3c735552024f268ca1658261bd8994d4cb3b4983abce57920515e055824a8c715be013cd8e82ef" },
                { "tg", "cd5c9ea48794688d1f27d6a6200158b3235af8a54631468cf8f59a578644919ea00f7ab5e68f37e8e8bcf4785fc7fccc86f4344c3e5004971a3a7d80070120ff" },
                { "th", "0623955a2f57d78d7e3184c0695ecc3ff35b1ea1e02a90b0b94ec9464df1f8003023dd56bcc51d3c8ac86f70a347ac911741e7e79edb0a6ed60107d708903cc0" },
                { "tl", "0f0317eeb6a2949e6b5ee54f1ffdb0783b1c94c0f2a1b9d72714add4250e41a8a23b46d74ee6138015d85b5157ff9f72eda45a2f672f18be7913b2d692e6caad" },
                { "tr", "efd0c5c7a6b3b235b1148bfe101f8a2e3ea5a74eabc3c909f06dd9131ecf73c01e9f762a990432f4998f0e26925077ac4889d3e1e8f9fbaf2de8e65f2c9aabda" },
                { "trs", "4676ee3964aab19761d163bc15b5aa091751753cbf03444c60eb2bcb70438519297cca58ec3c10751cde9f3733ef4537a196451633826128a474bb91372da70a" },
                { "uk", "f8d3256fd5ab71b7d61209c4fb485ed319f16c33e0a25644abe0d07098f03c8148d8066291f0729ee96b2ac78237486e3b9c30952db598592952dd3cc4fe7377" },
                { "ur", "1533b90159d70a4291d98bf05547b88e58187fb7e03490e0e79eeebb06fb7f96404dfc03d870d09018c7b144c0f188c27bbce48c6dc3d751d91b3b68533c41de" },
                { "uz", "aad7e527685d6df33fa5974dc2b89319bd8d2ea6d010e22e68e1aa8f5f54f7ecc17294bec5889602ea909306c260e75de3480f9052a52ed4d06ed7cf2a46d5ad" },
                { "vi", "c93e2eb1eb71ba1bb605edb9b70ca865baf57d9f57eda77295704c6f2f26531687d87e56cf28a175be30236d20e7ea2db831c5147d959105957b43fea3ed32be" },
                { "xh", "883053a39cd973e06145cb471e569d2658313490ceb7b8fdc55b4fe9c1b96f28ea08a498b89b4042f6c96dd0e8a74671331e2cc625e5a78ca12be26951cb4b0f" },
                { "zh-CN", "4ba5985544693ad6709e60918c3423bc9bb1f7f8ca0c7d1e3426ad31e43c149feb6f6498eb5234c01c2704803181414d67d3852cd0cfe2d32c63b13f96a901b2" },
                { "zh-TW", "f22b0ac408376e3873fd3223ea8e76ad41d9c90643f8b8506c4b4f9d4ea4dedf02420d07d6c1a67a933627292b3e682e6e8576c060a50c90989b39c1576f2bc8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "84bfe7aa489450ea2e612b3ac808ff7a3710de418e07b213489e4a4c2bfdd8cd430f5f103d7eb076a90e5bc2b8147a34975ce8d4cce513622feb3c88dd09b39a" },
                { "af", "082b9bb1ad996531e74f8b0bfce7806c453e286be2b2367c32126857c14c5a310f5ca931fdae8527238d6b840f6d67a70928bdcbd89d2a4813f4ef4df596822f" },
                { "an", "18ce350e616b8ed83faab4fb9af297b777a33eb5b60940ca3aec83cfbbb1f2e316c4cd318d1aa150cd499833b5dfb19e62fe29325fb9fef024f528246f22e72d" },
                { "ar", "703b98ede72b71533c93edefe486e2ce02fef2818342e73a5060ecffac0f7d268706403d5cf8a0693b595ec7499df00254b22ddd083c37dc3a7f30675629d48b" },
                { "ast", "5015d9ce9c8589fe7918736b39993c8157b7f7c0b503aa645635550b778984443d9dfb60908edfe3b61afce557630ecd75d474bbaeba9d8656469a740116f7f9" },
                { "az", "4557c97255845accec8cbc9c61058662399cb42249a581f8cf491785f42d3089a979f88e81b985134486393f12a6dc864236f49a921d5d0338102f2e0e86a0f8" },
                { "be", "273576874f5615bd441392dfee6a7b7d6b6574028d53f340d513f0732df4368022443adaee0a7584c8f9ddf485bc331a391cb1f333beff80c7589361a33bcfaa" },
                { "bg", "b90c852548f748120c74d35a0eb97a582775540e927456521bb171daa5dfd7ecac24464cff5483c46f5cf8b9e087dbc8d77533adfc180716ef0a078f0bfb0754" },
                { "bn", "152e446f08dcc528da835b499f792e4d0994beb33584af0672295ccdf5b7058902b86c04e982603fd1f2a558059857e9405244d278980e2e2d2d83a8229ae855" },
                { "br", "8987b5822cc14f9ff4f8c5c52e6683186581f0f45876eb2056e9ceba4c2d9787487648fbccfa398d8bb695354f178627153888f72e8704af47e94915ad6511e3" },
                { "bs", "6a1ebb97d3dcf9eabc039c2d3370827c006adb31c7b39139845f124e96bdcfa1788a9b74f7bc79a6ce762cc36d9d6688c4b79763bc9670d61330680a3b912e5a" },
                { "ca", "e578d5c91a22ebece1f0938c2d16b236ca0486cf4ebdca0e453766d29db8c21fb995517917173853d1aae29f12e16680a30ecdf9db3e28b91f47a9940d4632bc" },
                { "cak", "cc569a90e1a2d14c0d282561dd77e81a501be1b10b52ec5913c3311f255dcd67a733044f4c07b17bbe200cd85c5182fb4b35631b969d4913b9f68c6d588cbb69" },
                { "cs", "fbf5bd0360db9f1b78659186490a35da0e9c6bcfd0e91eb63865bfbfa8f45366746378b749fe5e082f60fb040f371b5c9186a2030174fed9d8748e941c726fe5" },
                { "cy", "6a3fe4478ac1c6366be925836c3ae7109fa31315088347cb63f78a5ccc997e174ddfa71ab1297e06ddb1dda42b961011bc7982d4f759102815b3493c3fcb05a0" },
                { "da", "41501ec8b9ded79e8dfb6333718835bd0ad7b02fdfa42b0b950b2663aaf2d03fe2bfa2fcde608ef907b1344aaa52c1099a0287b7350ca47025710a659a98ff74" },
                { "de", "59346263fedeec185aef2a98b41e0fb3dbb11788b420e40190d703c06097c3d00bc1711ac00e09a9aeaf479afe08b3dc4730deb5fef25dfc94502e84d9c2a59b" },
                { "dsb", "8161e146e4803e21f5862700171e0fee79b5395fe327b8c013d0802049f103170fce833fee5137bb1c2009659e8cb2a3a491f8ac05385398dc21acc55066c093" },
                { "el", "15acd1567af42aee283b6c6c5c1c805be63249da63825f196103ac4880c99b0ffb99b93488ba8106f077698b638915f796b73cff57959b533e8235e8ce814e38" },
                { "en-CA", "4ead63403a8e516e63381723ffaf702009e69a4b4f64bcd3fa57d91c7873cef1130010d752000dcec6991caf01976db68edcdc9da3b74a550220991172144dc9" },
                { "en-GB", "d34c5c687a8bb3aa2bc5fbe204feb6a5946fe230cf3dca1a4c3fce6db8c08c6f97e0d166bc5293736c1acaaff8c04e219cde9298132c9a8bf1d803caa44302d9" },
                { "en-US", "ad0555ab200706f7f3d7ee1e43230cee5bf622c9ed8c19a52414a83830c39bf689a1db51d34dac7c90891b19fbe928ee326de477d6480cc742883e809a3687c1" },
                { "eo", "e604db961f460cf43663812364d7f7595068f8b6a0e80ed3a11cc71744b93befb5ddcdb7f918cd205f4819a97cf1d366cd3762799a9ee7a5af930c79d66a7d69" },
                { "es-AR", "2a688f1d5b8ec8f29a14b2e1a1ffc781c04c2c56b66d505231e61b01cfe7d7e7337b357e6c064b26387e2fa858b5bb5d33ae50a96ea68a5c6594e3015b6fad12" },
                { "es-CL", "728fcee6f23e4b6aed8455a069d991cce13ce979ecabc61a00c27f41e0afef082ec2cb64e7a2b4ab21d050222e277105bb40ee337efbd76b8b1a6890452c4bd5" },
                { "es-ES", "ef6cb80f35f3dc08bc4efd3b6a2d880b113b2972beb9fa1e2a00d02d67c42e16afac40282be7887c3aa5e624ecade40782a245ad03baa6f737925436f5da9a2b" },
                { "es-MX", "96b160754add5cca699cb60d34ab1d404d50d2a05b414e9647e893b86484c279aab1d07a8ac36b04decc505eca6f6ca1545766d3c07e52f7c6b6fc3d7e4c2e40" },
                { "et", "078a7a4e7f43f1af8eeb068c4031bf46f176c58eda50bc82b454096d989163a3d88154e576c2bb09a6f60a1decae98d6500d75943310b90fcf192fa7026d670d" },
                { "eu", "1a23df436afcbf4c9ad4fe142d87eaff3054b26cf0f07718230906e0ad29542a0ea56e3d104114e69b7889c467b72f14655c962f4c3dd6b1198cfacb6aead104" },
                { "fa", "5a83028e3ec95bb9e27363d2381f3d8b57a0fb2bf1ed220f5a8b7cdef878bf715ea46a74c1c1121838b4e8da58c477e1db6654b49232297b83d773924de061d8" },
                { "ff", "aa3053789ff11a91c33db1778810fa7ef9b5ef463d64973335813451ae3e03549314609227cbd6275b24fd6586380c6439c27f25aaa6a8ce003fb149f6e328b4" },
                { "fi", "b9cd599683edca8e7f839c20b1ee19967f9cf6295a1cff4972a4dcbc8e516acada16cbddfedf9f5682a7d42bea13a810571b351969204db237ecc36fe4aea7f1" },
                { "fr", "2998d8978d4a3d1e8194ca56c204d174eef0165ca633e751526fec055ba826fedceab5f38479d865d575356e455fc63f331da2b6a341719205b156d86fb62f0a" },
                { "fur", "8996659d5017d103fa3aa83ac8b0cc8648ae9de50514a274772ecba8f56b506fa3239471dcc825e794df927db72781729a88bb2ff502112009083d2ef90b1f00" },
                { "fy-NL", "3f8e3db4979cf97be71f78100b5a3e633476f27f663a03cc5785915f6cbda32f7e696a28c4d0868397ceff0b6ed9d8d48a81f5b0a94a7dc3f8f785b80d0c6f33" },
                { "ga-IE", "734788233ed2cd0cea51ebbca6c4df471b6c7368cfa1a97068061f8a3755fde8b1f043b332a2610ad41bc71ead65d0dcae4a57c1fe9f00807d026205c85e6b16" },
                { "gd", "e4a6d4eac36165c5fbc9eef06aca04eecd13cc691e2175e5d946ecad23090b9d74aecef4d0a46ece2f5f08bde9cb126bb0e9bfabf76cd107adacc4508fe98253" },
                { "gl", "57407d13ef189cb326b665b55a83ea461b6fc65c9cd542a088c72230ed62d1f3c8d7a23d468e7f2acc8c78ed785c05d72b48e44be50a728dccdca129e427768d" },
                { "gn", "ea9107efe5066156599cd7094c533c67cfdeefd1fd737509ae0e580355e784b89a336b0d484ffaaeba97d9cfa962c3486dfca4b8f6413cc2015adf8a18337290" },
                { "gu-IN", "8c41b0ea745a8a9422e1d699e52b0b8af8947c9bb249d64e4649b8f48507c14ce44e45c67cf17a3110c5e6e5300e2cb945ae82734987ee366c613d6ecfadc22b" },
                { "he", "bab12c2c71ed00bffd7be3f9b13ff6ab5e42fdeaa660f8c29cbb6c891b8a83cd2b8c3cd0257e0ea6397619902eed1bcefd80ca2da2c60d1f08987370f7997810" },
                { "hi-IN", "9ce3a568fce1be269625d8923a28d5b657c4d55456ca983877514bbe86eb9cd21b4e2062589884fef970d8218e389f80325de4164504ab5539497b04de19b43b" },
                { "hr", "13c352c6f0644e4c9b05c24c55dcd5575c556f45a78463e5d602444ac28054ef9e31bcba1ebf3f9b23d1135c5932d212f3e3bed8d5bf4ad3b6ae1e084744dfd3" },
                { "hsb", "16115b6b3ba5b0a1e6182879287d83adc9305beaa61923a015ae0dcdd2acbb8306d2013e415dd1675e8ed7093e23568179dcf6af65ee7fbebb6ff6e88d36c0bf" },
                { "hu", "f438b8aad0bab7d238f40cf331595684d81ed2abc02304a35f505c538ee94c0543741369fb9fd30ce2ac7682e9596beff93a82fc8d503232dd1a58016aad0245" },
                { "hy-AM", "6371ac9d3ec37f7f9f25ee531e906d512757f9c632e32df4abcf594fbde797738b429e88420983cf6c8230962c505586828dbde8986e53cb6b311a120612b15b" },
                { "ia", "f83d1706145f1f555e57dd81d43d668f0db32c7a4cab08ac1017001a7b10dec256595835d7e9539fbdb766f6bb0342758fd0f67de01029001d3a5e2bb656bceb" },
                { "id", "b72899f1ffac94080404a13701cf225de2ce851b3a15cbf943cb4f031a43a98e6b80b420db96505350b7286f05b6efdfbd95eeb2656a68e9bcd821a61335be5e" },
                { "is", "7781cb01ce5a72ae309120554886d0a613699cf62ca2e0576e29d80b30c7cc7fbcb0baf08e69204166693b39bd26ac5d6154152379d05c458a343c46008935e1" },
                { "it", "caccab3c017bc09fee0a9f864702e094dbcaa16da800714135a2498ed034cd73d31c9746fc3615aecff5043f65ae2c2cf4c7b526b24533f636d73c54e5ed5b39" },
                { "ja", "2bc3472533a16502188247bc37d657c5c777f79f9a32efa803f0f5b24f24c781bbe7fb98e370bac9dee74a1635707409bf6b9614c16fdac9444d4e399326fdaa" },
                { "ka", "42779901d62f9b5cbbdc56fd2336b8a1b0300577c2e911ad5d0c3ca45f5da1ef0c0e7465ced92f6726298a95115b06f2ce0d7f99c319e27edc3dc642d8ee291d" },
                { "kab", "05d1f7969e2402ada8ad3ea65d83541ea7dbcecc137fee80b36b7e177c9ab0a29063c43926c9d084657de73da0da11a4fc4123db0b73af19055f350ba7d66b2f" },
                { "kk", "d8fb57fb2bf1ae124597f8b0c8e52d5362da726566de7c9cb9964a436aadf6ad99cde819cc3cbdcc0b7b0f7b25660736b06f82158352f7c0f32163ec3a095420" },
                { "km", "1bde134e1fd94b1138fa4aeda724017e0dc877768c4f9114d6e9141b657c84da82d8b9dabac65a34614b023d911fa94efa0b70ac25762a1087d18722a1754a58" },
                { "kn", "dbd9507cf38f605da46e54ca6747a567552cdebe08b36872f285971ccfd3dfe4dad7a76df156df98a7f6b31e3adb8d9f2d9f7df35a344bf6ad74fd1dff541d91" },
                { "ko", "9a9c0005aa4fcee0a5dec1f2900046a2f216539d3a0b610a1fa9bca76f5041436342858780e1b7a2897d489f39b27efd6a38a45009e7058667a69cfaee862b3a" },
                { "lij", "a41bbfb3eeb516a513e9cde322b70789f0ada4543cf07f6bf894478f5bcfedc304a022b01182389fe9ff49a86d2c7e727161de09fb4df1d9c0b23c9de0dc667e" },
                { "lt", "0c9181831461896b23a1af908800bc239f30ec7b615d9e38831b2047f7eb3f627477a24f509b1f843ee4e5c9a8f60c28642e5817ea119ec27c713df35544bd3e" },
                { "lv", "852d8789df60049cd20b07d189ad88231d2b04216065f9ac4666bba1fce099e6da80993d8f7052c19c6e9153cdf4e60b7761b644246c61211261716c22202d82" },
                { "mk", "7c1b5198faa9f03cfa25f0c860fc865ead746ec5e87ecb1d583b59cddc97f649f422b29c9e566c8c6bbd07a6af654719a8cdf1d854925c716a12a8cc8363f191" },
                { "mr", "dbfc9edefbe22256a22da5ba978bd3f7e59b72d8a609ca3d9e1e601af4be22a36a4c87ea0c6ff6bc2710a7e1bb2b9bf28f0ac4e0d4068fc9d5339e042bf9fc67" },
                { "ms", "18755e3cbf5311d8ccc53fb60103e639ecbd98b4576049ca7be7a6e0cb012ceedf142852b91c012d025014908e272427dd4f839aeddf2e24186968adb740ef7c" },
                { "my", "fcf59174ca1185c0a4b28bc6f4e7cbebf654871cf7a72e41c2842d057c8cf8cdd534c1518548412090f36f1b9c432d0d6c41e2724cc347ec2dd7fc086a6d2070" },
                { "nb-NO", "4e09eceb750c7e04a32734fb26944db268306e477197422a52fba7b0cda5604f8e0b95cbf888082bf17d5efdd7714c3bbf388fa84692984ef180cf79cee50ff9" },
                { "ne-NP", "75d574e3feaefea32209ffdf315428179cf6f815a4f8c1eb3bf032693c9a0fd5a7adc91800cfba8be9f347e68be43741b6a29b13cf5670f91edf0d504a9a7af1" },
                { "nl", "a7eb097ac9a8d1c2cbbe341f380568017fdb6447cde0d6eaedd8ca2d74b840f7a9b3ccacf6c9bb5af519afe551fcdd5e8f8503743eae19a5b209e9d4b8013a4e" },
                { "nn-NO", "be8878d676c81583869bc3b6b3c73259f5f9837f5374d8f11a4c455b4ad8d4d22a71ddaa8a21a9470abfa6617264c4730e0478eee1b6772eecac5be8f45cae4f" },
                { "oc", "37c3c61442a6dd35c38ce57019300b7a6f61faf1f96e5598fba7957d97f0c8516f9fc446d068ed8605473b2d00ebe1f5935eebc995329dc526c335fa3fafa071" },
                { "pa-IN", "6b18481f829d7bcb3073e17c290e00b4e27953fef171cc83f11dc3867333e84956a85bd12f99870d9e9000257624b3dca789ee8dee5da2d73875332654d077d4" },
                { "pl", "4abf46a348bfbe8f80832fd1e7ae9a238d8b5247ff4bf1be458051e81d7b3cc16bb8b5499be57df4aec36c2cd468f877149030355f9c649ceed6e444385e3b8a" },
                { "pt-BR", "9843e7bfdbaf1a77ebbc140d3992073885c27d0be357369933c85b8b4f2279328d2b9dee879f3a5b525229d144c9314633989a61a14273ed32aea526c7e0fbfd" },
                { "pt-PT", "861200c9ae7db0e9eba9a526e5ba39ae2db8473c3c2685c1fc63ff0fa1aa60e3b84e379ec160ff0bc2b9fc9d7010abc59e959947c11ff66773418f03b9c1c38b" },
                { "rm", "c7d83e3779b654d7b1a9818b3fdd81d0eddadf0b9171f0937b0f7724559b537f521751ea7f2004d3e8decc2806c5024129928d04ff06afb3e257a39dc8d73aed" },
                { "ro", "795395807701c45d244dd5082f19ac6dcc482744ca6dac76f983ff133edb1ca14e5477059730c90f8c3d435dd2650ee7b4f17ce73a677d927d87076f9c792656" },
                { "ru", "9a739a4f1901c1afe7620f072a8369c4816326fb33afeb0f9a0841bba4ebff7cd0c311e1a5729711cc13a9b61666c747b7b776367d6377bdc1690a8bddaa1f2b" },
                { "sat", "c0152da0787b8c561b463f109d08b04702745ebc1855330205af2205b34d504e97ab217f657e0653207fd259b828f3733f9c92da4a6650756ab6a9a2b4bff9a6" },
                { "sc", "8f35516d78c1c75ae7af305f087bb8a21b600042bd3e60b64f709179deedc1d0b5b394596d1d7f1b510dbdfb7b9c71faeff890dd26d1d70895dc4cb47fd9e38d" },
                { "sco", "f72be9e63dbe55dec7fb99373789154d4a2be0e0a45fbe1791d5c70d872fc76fffacd1885c0cf980876a7c30f946b14424639c09448b06c3b6098e0c144650e1" },
                { "si", "7834a33ba67bed4970ee573f17f83101820e3582e8a0422e2a39e66ef0bedf1a85a434bf84c1186126567506d927079b25a47589a1b58a3eab52af1dce90f519" },
                { "sk", "a68361e7ada8c6409abe04aaf8c69c0adca6a5d3ba9abc0f58bdaef124ecc962f78685e97d56a0d76b84060991ad64d61e5f298c6c733c68c62a76b6ee63bfa9" },
                { "skr", "2e72c842078b81e239001e6657b98a1a128b50d36cf3a9f2dfb7cd3efd5fedb3939914af30264a67c12082ae004505e552661d978df07d8ca523df9166eac13f" },
                { "sl", "308594e5b160c6fde0a0fc9f00642539fdf543c229e8f1d54f0c829bf8ec905ea47ad1f5bae164a4bb52cf2e07583a8a9534f1000e7da7ea8a3b7bc53c1e1e3b" },
                { "son", "c03595dbd54bc5a206a67df4ec621c797fe02f066c51b7239c89b560b1307b3576de5adb6400f2691f413d5927a128347fa851072b1eb01220b5e4159fb5438f" },
                { "sq", "c6ee74416d5aae8a5552683118f4ff49b38aff1d270a7c9cb2214cee3139608bafc2e6933b88f9da850e82d0522037188990ebb5d8f9e17a1950856f260ed8eb" },
                { "sr", "09a3d6a9cedae36b916836ad907febc7f07d2e62673337f2560c5ce628c76ee8ddcf1395fd944bfe79c589707a56a47ff2a676ac235ea9154ffe34ff01eba249" },
                { "sv-SE", "cf48642bff0ea174e6813fb763857d68dd9566ad2412eb526e213cf6d8a4df673f18ce5074d837c3ea1ac0d0f2b754cab61d413aeb9c4bfb01ae474f512677ed" },
                { "szl", "c3dba57941443000cac7d7eb52534b3e88cde257c43b29ad2192e02f14e471f5bb8e16e40c919092ca8f377f7c2369a880eb58575c26ee08f5334cede69a5b34" },
                { "ta", "35419cd4c3f4791e27093f7cdf43b5fd568e0cfbd7b3cae6a9699a0dd7f95b3d6950f52f6713e7dfd2c7307b1b0ae1f7b87e307de69871fb7f9fa82c6615eba7" },
                { "te", "d234095e12649b98c1d08f18a00ff359d467cd5ad725c5d574c90fe1c3115e19ef49013289217261d7be6cfa4e1231b173b68ab835fc864f545a98177914d751" },
                { "tg", "91c5b63f0ae43e4d4f24c507175f980d8dd24ca30906a3e73f96689a6ffd79ffb008fc00ceb9535fd1f3dae22be0b9f34bf01e33248f1e54395b58caabf341fb" },
                { "th", "04aba09d5b2c641c31770c547788c4279038aa192b13479fe7ce390f0a97168ba8117646455cb87847ef674c904151aadb54b04ce9a2d2905cb4ddc130725edf" },
                { "tl", "cb818afdecc7c5c2d906d0d05d9baa352c35580f6338f01581f906310825e63f7b6012b6e2686b8261e00e2c1e09fe8dc971fafe28042b09ca3f3606b0a2bff2" },
                { "tr", "0efadc37069bcea48f0faf099bfa87234739ad993ca918d7cce9a7d053c33b03c57174afde65dcc8fefb2cfabf48e512f2767d861f63a11cb3a6ae36018b5ea7" },
                { "trs", "394039dfb816ad9988c2e417796175cdc8b263035229366adcc18ede375ca6f091079e6064cc9b9de66452250c43a79ce00965070c53e9d03571797b5c32a70f" },
                { "uk", "221050b3089bf8257272a5b67ff27d7a6e11c7d7dbbc19eaa4a1e560dc41fbc1616587f6ee4440445a7296234a72fa52e977de7bb7d545f8434fa648ebdde063" },
                { "ur", "cc971c5c8a984f7a3525b3bdc3ec8fca241e405434fe398eb0a7c543198e4a422eb4582be7403ff4df8b8b9132721c3904440a4e056340618a5199fa1f3383b7" },
                { "uz", "1928356ace14fe88f00308734cd65b401246f611a099f9851d821912cf909e4fea230d05f6546442279f7d01fc22e765477ec6b789e31ed03ad83f2b5bbd2cd6" },
                { "vi", "5817bb0c288b99129a8bb922fde4a394db18bf58308efff8706ffcece68dd1494c83ca700a3abf1baa9fb81675b110a8a879cfede5b37b6b25d039958eb9228d" },
                { "xh", "3a2554d57800bede8e647212854fda22d6fae1ca53b6ccb0e1472a009612220b1580e4e30bca52aa0c0de8c82affd29686069b24bef85c3de81e550a5410d76f" },
                { "zh-CN", "0da6684e15d3d1e7048c845de60bf78ecb6ebb14d3f2ce2767cf12f0579bf577630e3dbc02da9858b10963fcbd6ed10eea6df7221363f6e7eb0df3d7890448e6" },
                { "zh-TW", "6585cc8f2818118219004bf0b38e8e3f649691c500560721f87ba85a73f9b303a9608eac3ee35bc0354d8e363be5320e786e36cfc12856f0d8c7779a6f241cdc" }
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
            const string knownVersion = "140.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
            return [];
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
