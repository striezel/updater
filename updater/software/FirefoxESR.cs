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
        private const string knownVersion = "128.9.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/128.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6de97699c397be9b9088247354949bcc1a2d3f128fa8211d811034a2a5493035ce4f28db984b6acda47d76ae9a46c939d67df943f88527ed2ecc2a39a7ed509b" },
                { "af", "7393f1790b11138a002abbbe3c81c5ba8744128baec2b27c477b0e8567e10092c1c90de17b2cbe68ad761258d688835d19335b61c27bfd3507fca2f815d8a791" },
                { "an", "89cdee6b13dd50873fce0dee51c3b78fed16e9b6a9e8656d3c3331a57733a09f2ff39ecec2e336dcc304568afbd0369b5bdb15de20321a26a3d7ba1365d7c0fd" },
                { "ar", "798b24c991adb888459b3711f6e4700e0de613ea06e06fa27e55c764d397bf3bcc3ca52bcc4869a7971fb8537ab359520fed35e3d293fd862f3b554a2080bb7d" },
                { "ast", "fb45fbf3bbf589657683cb0a442b518ccdb59918ea4aa9ee67a5c24a29da4ee8d7a60d41ac6445da8c45cf43d0668ea69da50b89392ffc0a61a2a8fcc1a64b1d" },
                { "az", "7e858ac0e5491627f3d10df6cca8f94732778546a19c6fe00f002af0fb114e5533f9cc87b0e3d64444c0873a15f3f5fb232c1a1485e8f0f525c94896373a8115" },
                { "be", "d5196b59a5d86c5c7c21268c67147e97f18db198d58538578d27e07cc5f656cc9781df6c962afa7332d2453708b921f130f907c935b023de555e350b9d47639d" },
                { "bg", "fbe8bef9efe486859f4f82ad3f4a6ffa2caebd86a5e4a29c79fa66d81c7e53c6a8220a11eb893598ccf38955b30012e84710293650d090480a776076e19c8135" },
                { "bn", "68a4bda760d658cf3cd17177e15b0cc16e98cd38d2fcc04437bb8922cbd14b17a88f9913cab581c4742c5f586e3bdf53002968bb97da49f5be4a81a035e10f1f" },
                { "br", "09d1913614c47aaef15f863783b4c17d94236a4256be20b2d69c0161bb8063983acac78f3f3af764c7b69ea46d2a98f73e54da976276619374c72d9966c82fb2" },
                { "bs", "bc19ef78a777a6bc71f6d47df778f6ed19bb8cc388a72be704ff532c7ccdb38257ef215525557e61e538fd453119697826c47a9089d18816c6c9b6b32ed872bd" },
                { "ca", "99cb62569f09a77045d78236a58af2bed529c1ce3de5fe85a487bbccee73886501c29c85f0fba78ccac4aec8315dc7871c7b8a9b2e40f4184234e039a9937054" },
                { "cak", "fea64c8f841af6a2a798f84a525e36c59e5d2f1c8873cfd71e3069958bfc84612a8e6ed84974fccd4de5825809325c03571a1d2da84a2b7303324924a6c50b8c" },
                { "cs", "a78a309aa7f72e61c76583345d7babe0531b67af8d3ddac8199bf083a4d8d7770983d60fe795719db37ac964fe48704f415437f63a35a8dda1b47cc14fa0b106" },
                { "cy", "d8dca5b48fa02ee4ed4071c6e50db3d44414b60fb7f2ed689392c210315f4fdfaa0e50df4b05940e7b12592b41d239af265905f3922ef34c87310600625222cc" },
                { "da", "ff60b2ff47f8804a3587fcc2cc884a1238473b9bdae0d018ff851ec2014c029c1225be53e7391a6bf4827ca42eef7289b37ab0edadf6428aea8c45dde619b34b" },
                { "de", "2f6d6d8a5cdb231d1e9a60a284da7550d28633344b131e76a92b2da337d183ec225709d8295dcb637194086f336f020850e705bee0a8d883a6e0c3e154319785" },
                { "dsb", "94c0fa3d1d1f4abdb9157a16fc598d4215f20079c8dbe1b3f75d4603fe7e0df155601a8b7d5073a65189163213b0ab5b6cf7fa2721ec65e81f32029a53827d36" },
                { "el", "f31ea601e8976d02aafcb2088184d33788622281a2e92ceffcdf19c7f4df1899c4f1b9807f28c4ea120acd8044a62fffba8277ed2c7fbdb0a36dc503952df2a1" },
                { "en-CA", "f6b41c54ab394c033406e02c0d80b8339da1c20a194ddb96f748238c2bcedb54851958c2e971533f917da4a8439c44666d8de485b6cf2386332d0e2028c9efbe" },
                { "en-GB", "a64f653b0b282a82a5ffb1c640acb66232871d612e7e43c01c18e7d7cf48c954b38a98c7f49d7921f00e753c546c6bbf7e61bfac7c40a5fe9ec826a900097496" },
                { "en-US", "5e59640fab27af9231e86259e5833fecaf6da7299c192be93cada328106530587c6b47885473a49de50fa32508c558b237df9eb7df828f9b9b5660872ed16de2" },
                { "eo", "41c8aae168fd837568ccbd3b69d8287e225498f6acc997072829900a17a8e0e757d6e3c469aa43f5c57c51fdd9cdf8766c629c59522993a96d01c36a87ebf61c" },
                { "es-AR", "f9b57fc7b690ff8bb614f108da18e9e5861718a8580c5fc211b82e726d1247c623ac3ad285406fbc6c520c74b2c86dc36d2d69fdb434d2a93ab29c72bfa3b293" },
                { "es-CL", "f7886e20144e1a023fcfed4fa3fa5b543d25e69818f9dce9aef66ad9f6de6e15e5f9cab768bda5c1dcc33b96c8b00d4e5e5892261053696ddcee6a93fb5f08d7" },
                { "es-ES", "e76878bfcaeb4c108aa637317517c768d82f3c9aebb6b324879feec60d412196551f8f067088a51018a715fd5171e524cf195cb13fcede31a9858d790cea1690" },
                { "es-MX", "1e413591ffe16826c213ca3f79ec20e693171fc28f2f7500f0632d531fa8676b183617ed328d1c92e6ded6ef65b389e5423aca2a249bfc717ab5a12fcbba3338" },
                { "et", "b403ed656c7bcf3ff8f614f6977af170346ad4f04d8c457b2957572eb5499ac75e4182b38256d505eae4f09926d2a18ec1706ff8628ec62354a518f865caef75" },
                { "eu", "95e3183915028c2c9b5d0528b255eead134ee8c3a2cd3634feb6c2d08c0bb28c92d9aba00acf4442617c99e57b0230dcee9566c50d1666d1f8c838166ae9217f" },
                { "fa", "f13bb115a3bf425182fb0defe438493348fb8b84de4e24ce43196bca84521616a0b3a0ced86774bf0cc148760530e185c6eceeec0d72ed47099f4974958b57fa" },
                { "ff", "ae82d2839babaaf404b95ef8c1787ce1d0b5696bc5ad608e92dc1502053dc0ad93416c9a286af036a4643260320d020e181fdf14a61d79ecb072af1272262f09" },
                { "fi", "64a2b66fc13a31ff39f0dff9f95c1810ee9df1d605614ca9608f1e41ddc900a61964dd651cdeb666ef707ac503fde807e6f373fc6119738c6198228ec08741e8" },
                { "fr", "6871a9b8219d961719db3ef681a0bef511c749c60a50f42ba06e4a4f46bb204b2ef7952f4b546b54bf5d9475f9576009e5dfb468bc96f1514f061b9fc63a1ca4" },
                { "fur", "d1a6d3fa82bd97ce55845cc1607c1f9cd51331a16e315742d55f35002c726c06a391444bd4ca4a475bdcf3d8d645ee459239ca2308c75ec627b2b597f143c630" },
                { "fy-NL", "e8985f750b0bd3c27777c03b1b14a489f4e792911ccae4c51efff02302b9f6a08e1360fa7eb0106f2ea6ed284a1579deecdac4201e6c9c184be4f64265fe5733" },
                { "ga-IE", "d80aea30155bd8cca05eb36463d009da796262ce86bb1e8448fec2c976be4a710532d4ad5d95de38c36010e95973371ce217486334ab7ef791ae8abd3ce81a0e" },
                { "gd", "8fd62dcb38b696f025f64b38f52d0b6d4d34e19cb02599d1a9f820c7eab8f7ed17e8bbbd88ff4a39b7a6f8844c98dd341ac1b99529b56fdd165b9866b53f39e9" },
                { "gl", "ce1f944d4ef84be5bf828fe1512aa358b3acd7b2f1ad2f4878e32bfc205a4f927024b55683e4f0322363a73e6c3fdc39d129db436256fc074d3206fb6fc1e006" },
                { "gn", "bfc2d30553032861ed431a36d886170a30015c9788da5660e8685d3e235220345c875762422be8adb68b940076401e28ab3de5b16f4cbdac705766da5270e49d" },
                { "gu-IN", "5b1639aef854baa3fb87c4c4e8f80c9782f55a82847005b42ad4558ef65a2fd625717bb8ca99ac82b5908b644f3df53a4bed229696eef8113737ec7d04de843f" },
                { "he", "54e94b47a40beb27eda0e012ebeb7b0dc63ee184dfca602aead7e2b124ab984eab27c9f76712c8ffb88130cffed29a9f32d955f281929f129008102cfbf95b40" },
                { "hi-IN", "5e6e18df4e848c683e6d220da94c04a8705bc79350d3a0803a9ef4fa361c4b67c2e3e50014da6a1944b84a9bdc9b12e2855342464811e6671d02b7f6994e0d02" },
                { "hr", "77c945275a8ad59f64dc1f5bb6669ca2b6ed43ea6db20040e8658b64c5dbf930d5a17fa778d42378bd08b28e3522dd61d57b6dcb3915af72828a67817d2bef0c" },
                { "hsb", "3ce4f5cea16b486f263e9f185252b60f48b22995f4b5943cd2530fabc32c649ddb6c3ad6f284393ec8dea6bf168157a8263ef85d9553c158de7f5e98f6baa222" },
                { "hu", "bc554ffba6ccfd69fdd7c325cf0957ec698e78587f459d3cf2310bc088436e4bb9d399fa0d5a5dea8208fbcccddf3bc2ed63e4554d35d263083c14ef8b0896a5" },
                { "hy-AM", "6edd69cbfb2e02b35efdf783f40937af2b19f83d73fd9c3556772c0bcae14415dbcc00c4684479849bd5263da72a53bc217ea48309467f9a32889aaf4b31851d" },
                { "ia", "9fbd9dc389b437c7d207cd089e042f616d2293531309bf34f274e500e437b7e034377427a1d556e0cf1c523750003a829c8c1bd3dc79be6fc5b888fa20fa5708" },
                { "id", "de6f6664853368b1ab285196ad50f3c9c4b7f4607f4695bacf9bbc8fe5495a8cc71ca7ac5bef26621edbea92d1a4f12487cca550f650ab04feff003800a3c6ee" },
                { "is", "260eecb9af168365bd26357fcd797bb95d529026bbd9d864864e0dbec8233763330a87d852c6e15ea2639d4e5a3fda88e85810c2dcfeda74195ac9b7f5e1ec73" },
                { "it", "4eaad9876c3bb29f355131a402310281facec3e15bc2de14585c1ef204cd8f2b4896fa13f785ea5ec3d297296b90f482861bf9b55b30457fc73483b97914af35" },
                { "ja", "6444ac1cc3f16d593ffd6bdda88b62b4aff8d2792912a26c3ff4c7b8b0963950086f04045f9202bed8793cb3203683f7281e2a8e9ea3eb1bc181b4c577b9b437" },
                { "ka", "a5a33b4d0e4b6d030577a2a7946fd2379139d5b3282a1526861b5a148282fea2351d2b6849b10381ae1897aa2ed78b945a27bbea4e27fa43a9fb49a5879158a4" },
                { "kab", "c5862c01c0ba2583287f32f2ee5f1c19ad72b5ad276b2909e337c06b681d4efad9078861f6f9adf6c459b46f7217fd26f1a6865f668302599319896a77857b4a" },
                { "kk", "d39439824a76620048cad323dd00247f7c1e7517860bcbd5f7669a656abef25e1e4b89196f04266364fe442f7a961a251af6c4aa6c7ef2073213fe43d2e61c85" },
                { "km", "eb0f4ab7fd79078f9f2f1526aa668b20f3c0c429dc43be0815bb8250381e91a9407c361ddb567a05ebe1fccb6b452226de44af7d0c0e2c28254bf10ef987a27c" },
                { "kn", "ece52af4b034da7b331500fd5bfecadc392cee540234726bc6b2b144b1df2df16d17268c5bd6f4a2bd5733fc92ab3bbe2e2377b37007d9c07ce28d3318dce6cd" },
                { "ko", "f3961fe2d6ebe10fa8ddf11f6379cf5d5f71c8210ac243fa413e1f45ce0c9fa3107b95a876c89fc5f44f63db7d7290915a42dd24db04fcbe8dbf0309e504851a" },
                { "lij", "2a013dc234fe174e4af5f9e0c0fa512d52106248e0f6237f7285bec9e192f55921fff763a544e3dec6c071f8a6aa9984ca83d084b4123a193a886528d31552e6" },
                { "lt", "03bda8e5d43300d282d7cc4efccc1b5e2979aec91db099444956013929355b6e919e5ff5c8f362fb5fb5aa342798c84abfc7ac0241308f39797402e8a7da7a4f" },
                { "lv", "ca2a249981234dc46be4b9220a7d91561e844d26756748cfbb2e9d16ebea19592dc72a4afb626923be0e8585598b58e7b224c3f3296c8a47caf90e140c434e12" },
                { "mk", "cc7f8d8fcb7c053620aa55822da4e871cb8f9c865cf24ad3ebb963df0acf97d4b5116f4b16da449cc01b85fabadb7bcdf8ecbc1d3b089e5b650d455b2c2089b3" },
                { "mr", "fe69ceef534bcb6660486b654b57a5968cc6be268af496143197bb3880076853cf5c02157b411d7070b45386360bbea10c027cb7b5c2f70b5c40d2422235e7f5" },
                { "ms", "6e754ed7a60ae4a52d8e9a049579bdf7aa56864b3f78808596a32ab85bca5bcbaf6fc66a51afc4ba4edd88acc689c284a0dae1fb46126c29d2b49a7a8c728860" },
                { "my", "76ea960b73f168c729f9f3d59a23e2cff6ead9b9e40975348635ccc52a6f71971252f7fbb413315ce39d5043ddd1fe79eea8a8635409ee59480eff77173a601a" },
                { "nb-NO", "d8eec51489b607977039dbf0811d5b4cb771777e4260d5f1392cfa48745f4fd30901f73181305a44c9a1b0f7718360a322588a7cff29305abdd721c986506435" },
                { "ne-NP", "e5f1a65688ace998f5517f9f2a0b0da3756e82acd18a5994b15f0ba4c161296104d742ca5fd456c4811203ac99b66474004f7bd65aaa5b0018a0223ad9a0bbbc" },
                { "nl", "f6a356c684124b74a5b38da19502f5511aae2896ea031bcb494a47da1a54fbe79adf07826178296bd717d4b311b739e46762c7e962eb744a9daabff77225ac6a" },
                { "nn-NO", "79e8bc2d825bd6db22e1cadcece7095b6f0f4bae1633dfdc37ead96a95df6a6c5a205bacaeca6c47565e7f76cd869e0933350d8baf76d6b96fb7047f7b8995d4" },
                { "oc", "dc867e8f26566cb16cf7747e5f7779a894c9bba356613abee9d1ca1ef0fe0dfddabbd257de964f953b6aa2ed58d7cb62041877f537486e58fc72f731f6c90c07" },
                { "pa-IN", "4e1fb3ec13159ea47d73768b64052847219155ab7e6001c147f51367bec209f3abcb740641b0ee272eef7bdf14d9ef20e14ffe56a1056bb41118e728bf4937b1" },
                { "pl", "68eff040b0aa94aede7a4ee23829da53b11606b831c1e367eb068f26066a8706c9ffc475572b577712cb97dfe243661d69ca765fc6d184aa62222ea8282edea3" },
                { "pt-BR", "fbe9af37d1bdeca7d3166e02a13f98bbe8e1523a135328721823940669e08f6bd692566db7fa245213a8a9cf006a07ccb18a7f38e62aa37a6273178c8563c79d" },
                { "pt-PT", "c6955bc7be9407c195bda7a8b9918ef1c1601037f4219f9a7111662a9e539f873a9bab3105f72f0ea4880022aa0265799fbed8897009f927b47d83a766fcff4c" },
                { "rm", "c317fbc9198aff026cff3668159ec1fcc216f1d1e06740070ccbeb976b952868eef6fd228243f67c158967a2e6437dc523c7333a365c72afdf137611de1f7daf" },
                { "ro", "f3ccf002521a96a234e140ada252a9519727c7abafebf94af24ff18861cbd9b39a175bae0dc60f30956a9d86cea0b83e01f85c2b55c0cb4b1a87cf2b9c362b55" },
                { "ru", "98a24505c31070d9f122ef7e2d76e6732f1566a2cbfdf40abc0b1f229459e8261c01fb2d46352b2c7025273da980e421bf1a4854024e97c923de9756830123ca" },
                { "sat", "a432d58fd37aa0b4d6ec2664107b79cea0633c2ccb65a28150b7696ad3ff7c558f672cc2dfd5d89f751a24d2b58e0cd2a2e0626d0a79cc8b772e41f1a4f8dcfb" },
                { "sc", "53ff5ba2ad0bf9db37cf82687c51b1de2333ea15355bf2038b8ec73e2d006f97fd186767e76ae3e785dbe02fa0a15d39209ac45b5f231d153e570dc14ec91c45" },
                { "sco", "3b00e1f56965b5917490f6332eb308a07b4c58a81888cadff187f531ffa7722518935841962591170281e7cfe3a186b5fcf2b68da19a4b3aece389d95d360742" },
                { "si", "5d564a366b159e947463db00a3d53585405c68b7d4d56dc45ee30d55a542151904a6d822a493db6459c4dbd3188b433c1dae32f3690b79189c72ea1ddbe2b0c1" },
                { "sk", "2519fe084e8191f1993e26c4910d15189897860e18ceb69b736ae85c848092176a39872a42f74a199bcff4a88f34cb031d1fdf1eda9e71483f527d879b880290" },
                { "skr", "c626bc09b975b331422efb676eafc22031ff1b5b465f9487a808d3e9faef17d847cddf4b32864ea357e8bf187cf480616410d599944fd74e1f1325bc3a0b2e63" },
                { "sl", "9346c6d68938be5e4d7e001a94bc941954fba50a67e132eb5067fdc2a69525e0607958261a407f74ef0e8fe4e1d44544ef50bee4b3fc5c1ff2ffdc68c097bace" },
                { "son", "196df29c667752c6de4f89521c2309a423686dfcaae2f0210440e19c5f4dc41e8892a7d6761f795e70ad77f6b450ec0a1837301ac5ffcae46971938c038793b1" },
                { "sq", "b8a1fa73361b7a82078251bb5b0417da2eebc442c0669476a152414f784b629c26ccb92ba9b36e59cb44c1103381f8cf466350e3070493645e0bec894eb35362" },
                { "sr", "45a5c7bcc4b9cb0ce97d8f0c3b840fdf787d25af7c5462518493be9525ee01751fc451be6d01c1a31a73d6e4d6f0bea221552712477d9e40b0ac1762622a8487" },
                { "sv-SE", "e99438730e68ff3741c6387d566ad1962008f6097a89645a541f1881768b5849683ee5fa52445337815e020e1b65465fddfdaa8751dbf204a34f59a9b4ab6672" },
                { "szl", "ae0baae6ef3bfa6d00db1d0676e618822ac269dc8c0ba4666ed69255fed9e97e70c235354977a2618d782c5201bcda7ede7153775aeef705a0479bb7107ea94b" },
                { "ta", "f81f18eabb918af896b282f528bc8d9c0c97cc0db361599165b3e6e1369ceed185a4ef15fb95b46264276e6289ef06204156eb964a87b7e1aaeff93aa7f50e91" },
                { "te", "c32dadf57c387b15993e06c61a0442f3e13089b9d5a86d74f302cc52e880ea41a3bff1b4c5b7dd8f6139f0204c60cbc42c05dce7b45e9fe001db81157e992b2b" },
                { "tg", "70a45207b45e525cdd54782c25e7f5b0a884d3376cc1eef23124794ef1c65abb5e430664dcd8717b57880b6c583115bd75132dc5d55910179263dbe5ed1961db" },
                { "th", "2f7dbab8b6d89ff404f10b22a884335ad54f6fb67a1a7e8cd197a1f3326b351cb86cb6a08501f9cf3bc70caaa5a679df724e48d506b07b8a17b5954666f942ad" },
                { "tl", "d6a1c236039daf3bbad19bcb9d73f88cd04147f783a8a28f42e21f59bbc417f076c37c957c5e160a872de9e63ea065015a0c5d0c9f645a027584ffb3741cc4be" },
                { "tr", "deba5b3f41a5d3d91cc25eca06aa8dc26433bcc2d03f863ca4ca5b8307cbc49ddaf53193c3e5a432275054c899df711ce1749b8315371fae6ddeeb9a2eda834f" },
                { "trs", "ed67361c43273d01b226a0064d0565a3ae0abf219530c4bc0c881bab675599ad228c9a76515b5c44caf7c2b48d75c05e0704f5ca2033b7b0fae7afe5bbbf36be" },
                { "uk", "b8d6c88bc1f39faaf6dfebf88299e3a9226b2f002ec58c7689bf363b48bf742a3b618fb0314fa3c86c79c1574a9f2520f8be942fc6c60916acee47c3110c08d0" },
                { "ur", "0aedf8c4cc9452375b4f4e7fc16342e6be39ea7c25fc9ebb08594764ef6502c2e1b0141a51a4e1b86078345251445067df163458fee4aa9f9b49a02bfb4d54b2" },
                { "uz", "3a8e400bdcae2a5f72fdfc865a45e9c3fcdab72572353293664886e2480065b45732bb9ee1a66f4b089260cee6c03dbd6d82f0fdfb88236736edaa6d211224a9" },
                { "vi", "88e0f0b7115b943f9b1819139678522e5e181b149622e5af168f606d8cd29fbd7ddf0592cb22df84ad39792b6f0e2f178fd8866d70188155405c398b23d8d4b8" },
                { "xh", "26ca093b842ee10be180d63a5020114904e06193831889a02962fdea568007b97b53bbbf051fce2d36879fd09dcbdfa53d3f89b8c236177eb058feebc7a6258d" },
                { "zh-CN", "e15034cff8ce0d61a58f76ec83653782a9e5c298e49c5204057f1262ae1e1c9ac9660cd5f994439f9f64c4dbac1681d79a22d4bc71f590b5f8cdad6d487a5e8e" },
                { "zh-TW", "315d73769a629343db68de3e6a929fa2e21264eda3ae168ea6cb9f693e4229188fe35518b68e3460aa7efcb35f1cc06c2c224563290329b8e77bc2c6259b987f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ff4bce52efe92c0deea1ba8cc7c9a8b7548f69374dd72174a76eca4b419402f540aca1e3a9846b610747ec431655c18a2e07f4ef170d06fcc8d73759c3f55d40" },
                { "af", "3acf9f163a11eab2100a8e63b6682658223963a6fe58ccc0a6aae8a86478016773abc04eb4bb8657fb67928bb0ca96facfee9a0ec61413dad9891e021d350054" },
                { "an", "073d3bd83301e41b8a70c16f784c64583231b5158305b206ad31c91ed9f4f1b5ff2c00466f09c8ede4f87b2a2e3e60b89c3417857bff6e825637d0d87be9b09c" },
                { "ar", "bc3dec659bf2a3bd874558b46cb200d0ebb06fd842c8542ff717ca11a0ff636d07a19aefa7dc2f48402413007781664e828dd390f98c8a6eab72cbc13894015d" },
                { "ast", "9c5694fc8813639150d93da84071c87cf1ce8e16ca886a2eb527fb0575918b6fe6fedbf37aacb56536b72a452867949a1d20d68f351f91517acb0f332133ec35" },
                { "az", "adc44d5666da28ecc0091b95224b8c4e429a390d8d2faf44daab9e44b745586d2d3fb44f0e8070fbcc5ab1d2d47e58df965549c37504c86344d425646a0cd5d1" },
                { "be", "1ca3b2fa76d7ece22fd583fda90164838e5cf19e7dd4bad514ab24d8ff755fa463a8ec3b2fc7eccc09cd36face9b2724c238e2a2370f9c96ed953c6b1d07b218" },
                { "bg", "ddf9cdaefd31986bc0c282a856b26f1de68078e7a52a6777d458602430edf6462e129b5cc4a10b21a9bd85b9ec42c7369bf7148d80ec10125365ebc701191e33" },
                { "bn", "df9009c4c641587e9778fcbf576ad3d86c96ffd59c944ed08680b30534787c51d38cc38a20e2a63517b7c2c86e0a4d02857ad0aba79e1340cd1ef37f5c8014ea" },
                { "br", "15ac79f6ba0fceedb2762bb8565ceb9e27c80860d8731f88759ad258f129b8a5a69c429d650ddf368d22b608e786db5baf350ea3b4765089b9db6016e313a2e4" },
                { "bs", "1687a6db82d281c0711a7105367803a83d98c347a80eb80e84e0bbadeb6f9df5fe8b266ed912bf5a7aac8212daad10a2fac1ef697dd615efed77b78b1c6828ad" },
                { "ca", "19d9ab9dddac5cf7062b3c514ad27a957ee060a6751f19f46ee5a3959c1e5e6ce6e4ae90b519b0530876e45376de71b4afff8d33ad1b8b123c7864ec6b12df20" },
                { "cak", "6f0253bc8a4fcd787e6a412021a9c3323e9797c76dfc9dfb5ca8deab94ef3551bb508677cac5662b47a51148f3368deb433b99947d645552c81a69872c060665" },
                { "cs", "6d1e263f3b333a53ddbfee96c09ce4add639ae187a026b82e1a854df1abed149f95087e6b51ab812ac8fcf892fbd842456f79ca0958330d96a47cba557d18cc7" },
                { "cy", "3d17c26296451f428a98a1efa86c3b5e9dee0a4710a370cf893eaf40644111695433cfb6c17d9e6c6292f8d6efa9ce5bb8b4fc6071b3040dd7dd968763d6f4df" },
                { "da", "071496ccdee7951b1fe30453359bce4418cdc3f636b341d0b962340417ac6d753c856153c21c7278c76f4d20190b2f31143b4b0525c0d8eb6f25514cab607590" },
                { "de", "25bba7b5e9477674b783f667b471963958e497f5820826e98e7708594a468a11d7643a8965c951f34e384a52a04a5af36ad8210711b7c8d306d3981a46dad6d2" },
                { "dsb", "a2f41d09e9f202d56ff77e63a0eb8b2e09a50857f015143b7babc019b66bf4bef378bc8289cafa76c7f8637048107d1c32ed2dba60c5644b40668a260de7d9b3" },
                { "el", "68879d6b5eedd5b928d3a2d65619a0734cbe0f6e07818ce23a378db3a14c9e3c0f260f30fdacfa0e9c562829105620856339072bba0e70b9fb308d86c82f0e00" },
                { "en-CA", "86b9a7676b0d029c52b8b4ed66c1d5910a248188771fb2eee07b14fb68baf4902ab40758360becf1e3683dd6e6132af9221e29fb7081410d67316a682ba4d9ee" },
                { "en-GB", "4bed9caee9c9318cfa262f2ae52a3a0da598c54e2483e4ee28f907c40408e265b219a46e6b1c605c32c459f738f3f7fe980aa65cefd628a6c5ecc8439e1172cf" },
                { "en-US", "508367a391f2ddea9fbd072356731d00df537b37daa2f462a7dc9f8cf667840787bb026834e8de45c2c0f6af367afb70a429f3c15e0d6318ea53451dad070330" },
                { "eo", "5eab109f96ab29367b55214ba8fdc5c30048bf5289cbdd7ea35d067b81091f4823077f19068ad195f8ed3e49a05f7b5451f0b172e22ca3351544dcc4ab657115" },
                { "es-AR", "0cc021bd0705e1e332433b8b94e082321ffffb4b57bb7d08bfd225b22cc7db3c1c65f136e2a3c81383a1443df7eac9e56002e59ab87689400c2a5985efc83f24" },
                { "es-CL", "e04f8dd0b2fa54bd2a0355e7409ad0c9aedc555a8d4c83e44534911aa1171498772624fd7612795f4fdaf2b3b6eb82b94c63bd1f1ba99a2a0cb7c73d7ba01c90" },
                { "es-ES", "0f2e7fb0add2771522ce8af4b24c23d93b32eaf460af5f6480a3c99600d61fa0dda8d72bc80af413e91a8cf679461fd5aa708cc990a5695c2394b4422b235f33" },
                { "es-MX", "2382f2f38ab3aec69a53c849615fede81b10b4a9e902d04430b0cc8c561caaeca9d2d8d1a6bdef4a666550231cfa8e366577a6c4fa6d548ebde31b5031acce26" },
                { "et", "31746ff4281714b25af2548c174fe8e4aad3a9dac986d5e218c34725525a3b5e2c72c3f68b212f5c5707b6e40462433fb15365e1b49bf4517c26b862763f507e" },
                { "eu", "8c3df49307f4ca9a7ed3b190cb1cba855119c600457234ba5f0e56006ce8c96d6e97b988c6db7a44ba265b1274e4b79685d1bdcce121e1214853c95f64b79bd9" },
                { "fa", "3dea8740ca47691206f85e2dde2d4a2a116b9420fedc7c46f7c8d8b68a44b8865cd5028ef78a6a7184096b9865343061db9df507ea947f2e101f8aec726e2532" },
                { "ff", "757c7ee81a9f69ecf8767bb873726e1d094998125a2f3f352b93b490cc37d0b5815133e520901f372db658c0b8217b604c1e61ca083ace255f8a914353cab6a5" },
                { "fi", "3b02f26eefbda7ae84bb071092592313c5511eded40acbf3abce49f76a881e6f3736f50f5e6b7baebdf90385ae55fc58d66ece37d89395009b354ffd0245d6bc" },
                { "fr", "9cb0ba3b4ea0b308df267ed0bfb3e1157e51f5d8827a0fa831822785d897fbcde3bcd0c880488d14175c9769d509a77727083ba44ecdb2086f6f9b85297c522f" },
                { "fur", "969ad17c7c8566779f4b1290070384d9d0052eb0dc43ce153b861f7746252adb1f19fc337e386a4594cf62c63174253163df8998d06b94b02108d5d3ffde1f8c" },
                { "fy-NL", "eb08c18c34c6c19ef90f3ab7a521f613418ab2aa67a06b3c35e63d51083583559517a41ba3fe9ae0d1938708146b0c76576e4ef83485a47cf6af961018ec606c" },
                { "ga-IE", "64d188a081d1454ac513cab4e0825293180cf116defb01a37679e2c59d81894695fe40dfc1eeaa055c952a63d08f863bdb4fd243549dfa27b1a7c999e9db5ade" },
                { "gd", "d0eee76c0e88af0f772c2bb736738d3215ff74790cce5b08dd10c0caf4876eb725cc38942d42660b348844574917c4bebedeeb046a936acc662496fc7dc4f7b0" },
                { "gl", "e5ce15225cc483aa4edafd09a3d17ecfaae54a3813059b7f515e1ec98ac4e181512ba2237d030951e21646bff87b3267eb521f374c3bbcb8dccd8546c4a6434c" },
                { "gn", "f391bb70329f4ec9913918e3086148c5f8fe18a1bb093af31fb6d22fdc64b95e0315d1894818cd6f45c7e6ab2b8661e61d1dd78015e47ecdc43731e372f0899e" },
                { "gu-IN", "31cb7a44b741a1296522f688e432835fc9d440affd475b02678361c0905c2645384084634f976e26faa879c5cb6c14f2424d27d1b05c2dec10ef79ca1ca7dce8" },
                { "he", "1f4ea5d8b41113fa4b8e0272b2ebe4f18d4a3c88c56121c5943a3661d8693982dbbfa7f68e1a4d0baa64a9fb17e722a2d1dbd779c744728fddeb0467b8565460" },
                { "hi-IN", "f6381a22c6d0a9bef6390d19ef3699a713c0c94176a9ca87d783f11b94ddcd9185fdf2c470da05b410f843504672e1ffe72f7f0f32f230722e968e2315bb383f" },
                { "hr", "d33dab2b54737e3008f31955bd8c8583c0c9928b605f1054cf0f2887523d7db89bae0a2ef3a2d5ef7305a496e1684a7bb2e2d65f66d937c950617b5e9283980b" },
                { "hsb", "c72ecac0b532506beee0ce80fc19f52b6b649fdb1516b43900794ab2ad6f8ee6d2e230751274e8c329055b50dffb340f26195b82ea8cf700fcfe27b3acddc00e" },
                { "hu", "51e0ebc6b98ae6904dcd13f9ffe6b088636ac50b0821736eedfa3adf30eca731be01a25f21006f7d842d4bfba8cd9a1189a73d47415862732b79a49e9f475b6c" },
                { "hy-AM", "04bc3c0f6c6fd0fa7fd55ad13e1cf403626da095a5acb4876e11327945b4a8d85aa6b48948212b1516dbb0092b5f8e940155ba0dc7f0ae43aa6cdf07cacafec0" },
                { "ia", "9c89ea63f49eb68ba330916efce6e379fbd2ed3cc5ec5b9ec21d9714382afd223569fbdd106694311c6481c3769d631fad19e3b75913feda0b8d28375fb315b4" },
                { "id", "30d1e184615ed5927488c54c6ef60e89a408aab16d4d313bbc452e200e65b398431e1640182178022b80474b4f7c05e9cd2268ec1b9baf5f5926b8091e09b1ef" },
                { "is", "32db9602cf19aed2a64947b0172dd95f5eefc4d660a6a1a8f2af894452c03cf284289f8a97379c1f148c0012f3fecfdbdc290b30007a9e0d66033170e5eeb8f0" },
                { "it", "4772bf5e14a96ab71e0097ab067e3500ab70f9080626bd721ce7a98f3b884305f1421df1f7242c6ef0fca21118c8c7265c1aff8149887296c7515a406ddbe318" },
                { "ja", "613e94f03f0f113f5d119208ce5fb737aac60388ba068d0d8acb27490bd8c8c614bdc268ee3604df0b812e4e266affa47352a87110281957f783fbf750d55c85" },
                { "ka", "b539b3b75c247a4d02966d2428937ede1f29bfc140388391b4730a619e907aca5784157874110009f69db48519ea829b8b091133d4e8770615c15e74064a1a09" },
                { "kab", "adc5cf5d12e56a78ec1894c8a636a6df12fa4f8d356ecb0d03edecd7bfec65843ef1fb8ad4f99c37722d8fe4873b4f83f691bd5144b4775139997499f60a2795" },
                { "kk", "193ed2c18a6b587b7b11dab0549a9677c3a0df5bdcef212c9bb6e6b918fbda1facb9ab944be44c743bf9c4a421491c7359d27455665e151cb0bccc8aff2e9a0e" },
                { "km", "66d082ee9f91f8922ae267ed08287d5d4b01a79509cb2874508c37b26a80f67a9fd6f0e3f1396ab9159eea901f7fc80327d83bdf9f4f36c7a54510ac45387a33" },
                { "kn", "37d92378717a6278e8c3c7ecb50c68467cf2fa96fa2c6d16dd1feb311de6b6f8e99e639aacf9195753c1de9f422ce87591bc75453bf16a3bc4537837e191d3ef" },
                { "ko", "8ba07d6b1962f6efb838174a2af1cbe8619920fcc986f197329dfec291965e71064bf77516df90dc29f9d88418365e26a7b09b48f685e3887f91decf0b30894b" },
                { "lij", "1740fe679689b2902b57ac9a644f415488114c76c7cf8a81f77e97e1d88e142dc66093c24ecb402343c0f1526f0fc48423e4c247542d58c6bc96db5a8d69b116" },
                { "lt", "b14b0435771285a4b31ef364a1840f886f57fc7df4a72a44984413e39690357367fbf9964e3e710db842c1b4ced08a1df3d0766491a9b792e6ce398ba1049868" },
                { "lv", "b6abbc2f960b97624d907c1240e170aa00cf86ee31d75972ae1069f57fbde944855f9976299352f72a640f431fe6e4aebbeaa9c7fd2f99910257334e97905f9a" },
                { "mk", "98cb170370cfe119ffe43f13747401c51fa52d47ae2f933ffa6ad54ddbd52dc6e6b5c7a3d5d9768b8e92b6276fa26ac2ce208cdd8d6c0037772d9b833eb8f031" },
                { "mr", "8f01f830b5d34d1f60a93046b52d88c18e4563bc326355ca26be4a787d3bdbace54a306cd67131ce73af5416413be882ca2a48ebdf3b75bb1f7e2ba34d1a193e" },
                { "ms", "74347ea1f733c759e509c95b139ff720419df48569314c9c610067be978ee63671e0400478c9412a1e9b0961b3c94852e9d793a71daa44fc0d12e2800b45fe5a" },
                { "my", "27693ea18eae4bfe6b84500533fbb88feedf3bba45e20a3f7d847a8f1ef4638edcb5d606350d8d1cdc4306ca047e105214de5bfb6870ee2a7e99fe506c5c464f" },
                { "nb-NO", "09fff87bfa180c618af9defe26db38bec586c0c30d2e694bc52a276b629dddac4a87a0ade59ff57c53d7090979cb4bede908b56f692c10bee2fade1d0d35a0bc" },
                { "ne-NP", "524c39258e3ead79c96db33bf65bee83705589ebf6f693e3b2949b02d8d388e0ba3845cb99801d71754d55b22d14a670a5b22755977704e1e464784d98800e2d" },
                { "nl", "eb520e741fdabe23dce8a409a638bbf2ea2b67063867a4545ced3595c870b14e683be98bb1f9877fb7d8c8c0a097b28f73ba7fd753aec4dd0604f8951c974077" },
                { "nn-NO", "40142c7367f3d61c55107f9a83a714e6287eea52a93de8392fe762d2aea244846dae986fd5b0897914d29523de69040496b01acdebb7a0a5446dfe96e8bfcf3d" },
                { "oc", "27bad10bd4b85b29946bc7cb8b641a7b40177e8d1962ac49ca25c7872927988d4c10232f0b1554208ebc73b06dcc6825aeedf39a41a4f2b915ebd25fb7243aa3" },
                { "pa-IN", "3bc8906a24b22222db3de80136051dd2dec1ff83e011d87b07a0a6f50801841e2738d7e5209bd3590385f0ef6d563b99e7623081052b853f7c784745bdffd5a0" },
                { "pl", "ffe1303cb65010570a6100515198b63d6479e0fa591c4034edf9ec933d7d551cf673cd6d042404f3745f0f2ae095d9dc093b87fad3877c62bb378d34efc6a8df" },
                { "pt-BR", "3a702044d1cb7c193793076976e22bc5ff40cbda9f3508a46783598ebe00a92ce5d3f7db45b638aba9f4389ae1540b90969069fee599ba9f513bb454cb26c2bc" },
                { "pt-PT", "4f6f4f780705d711cdd2f954ed7481ac2d7bb38a18d5542c3e48c260768f689ee327c61839e60323a8f51d0ae56521a0627eb9ec169063dbf94b76f4c17095f6" },
                { "rm", "82b3e00969a9e18a17bfb0676da0daa6e3875ed4ed5dd50d1d834af745fc8444e4c7ba6f4a6a705fc5117870009b0e92e6014a22e81f6127b6871798e8795743" },
                { "ro", "2634eaa966f5d044850e984a8543a7f7607f0c81a43fe2de9d62cf5f7cc9e63bb9201450656a971bc4ba3ffc11da60a259f9c163190079056146c10db9b57e5d" },
                { "ru", "a3400ea5bca5a051307cf924d15c33e2a9984f0425188b421038071f5b3c4effced54b3c805dd85524d663564cb0c6c2e49607d6e5269cec0b5da0fcb0d2fd96" },
                { "sat", "213ce2fde773a04c9ddd7afcfbafe739a08ae56e410506134dad23a99e9827fdac2ca549872f562263edd779c8c290a2bea2501c2b1d6c84f3cbde11def83a42" },
                { "sc", "04c4393d206298e305546292ee2807f4f3b49deb2478dec09632115e1b6523724d598f8e5bd41f86f7cee0676a6d0e6b7def324fbdaa63234e0b9d676b37cec2" },
                { "sco", "d34a6224e59110e81ff1a2626c61e2d07294fb9459693d2c9aace826a8149045f955f3df8d1d5f0b5c6851cc0265608108fd23e8d40b8be5a03f8f08f497d6fc" },
                { "si", "fcb80584bc9564d18168f7de04fc6214f400c730b59a5714bcb51a2764794e6f9e124f9fe1f8fbab911e554dca073ef688ed9294c769716b6114947312985fa5" },
                { "sk", "7cac17eae9d471d50fa514f76241120e896dd8cf00bba097134020a6c3b6e1d4f69f4123e110092dae539d48d2eca4d4650f8cbffc0cec258f0008ae75194e3c" },
                { "skr", "128a897d2237e38fbbc0137b352d7ffed15e45b379c84294a73e4bf5b553908900b4971edff0d02ce8be63dfc378c6479d8a6b5eed60870463e7e67213f42477" },
                { "sl", "3ff7dcc3429e91c49700b592d82c6b0d8961ba6f237c0cf221fc56b58516597add6e69c3eced8adc49bf36c07b3bb73e0e3fb3e0328d5fee6021045c4993c1ab" },
                { "son", "0c1f4b7ec2c886a05a9e5307ac8e6f62b9cba77eef49fdde42885188fd627d9097329cdf78e87b4283e2924e11b3796ab4de0aef75adb33c2f3776c76729813e" },
                { "sq", "5dc25c21972ae74854512debb6d9cc47c0536b4838b225d4e43566999fa18bf118ade299916ced88de29b0213e0a8fe4301e4c732e052bacd1b5ec5ce1cbdefc" },
                { "sr", "7b7baf8cf92d5321a77dd70fc631a40c25c33c67299c829cb2c0deb32dadd9df1d8b9bc11cf20c23f7b7d0c7a0d477c1e1ccdf24478eb365e9b9b6fcd927d969" },
                { "sv-SE", "e05c81b00e1830e191dc2f550f07415c81e0de87dde3c75b789df7d210ac1307f4afa2aef8c19982f337ac49d3bc6a07eaab3ee5a24db65571b6d78e322e1b2f" },
                { "szl", "f27cba9bae63cfc8fe94ba25d9557b6b2fdc13fc101ed5a9f10eae5fc96a55960f6e659fefae495da7a69150d32532025c6eeb893b0719cf0f894cb1004ac07b" },
                { "ta", "6896da19b833951976a2a9d0042b095bdfe009fd73d19398d3443dc37ff97e65b5403c9047467a32156ee02ecae649bc6d3b78b1758c4473337ac65511ddf55e" },
                { "te", "4050c62fb3f884758a09572091269c924619458c366e87f4e923ff73ea4345240960209102a0ad62036a913bb2dce35caeabe52676349ca526b5a5e2f1339094" },
                { "tg", "33c07a2774723e735f8d5d55ee94aeba15b3a1eb6747d8a49ca257c02036fce29339b4a660b6e87a90a919930731e3da2016a96700c0cb970db00f16222d0de3" },
                { "th", "0e8846b73d4f8a0c36b0a066414f47b35a0821627e0bf2f8a292647fb1f532741ccf76a600b00618f2b86c235622d7fc9dd31546e111c4513f292b696153f076" },
                { "tl", "b1ed1e40fda3e40124001db2a046c82d00f975b0517f55b4a3a6cc3bdb495e9f05930c6c6222f685edcd89140eebdc0a90c5954c9433dd3a98595e6c74c7d0a6" },
                { "tr", "3db07a1fbc7064539bf52258b4f2d9722d5b35da539310a25fbb1cb564a2d46212d35620d5f16a7258164d03d86d25ea04612da9448cc0aebd584cffd77506ad" },
                { "trs", "4d47ebd845dc78af5aa6edbfc138c92ee78d5d1f89f06d43f43baf5de170e1a3bc980771251cd1b4e7cb1480613a1c15c6ac82c16b2e5ef3017edc23fe5c118e" },
                { "uk", "e7571def3547fc864c446a4266070685ef5972614b670d84726748f4ed96bf7be7e64309d25582413c3cd908e6bc8e9624263703031e10879887ad4f1939a52e" },
                { "ur", "13221d3708ba44b1169be0991c628a9de7a26ed91725056fd03fd3df0c95321a42cc7d009ce01b262a6f80f42089d6f22327f790ae1bb9a8aa7abf452cd0dcf9" },
                { "uz", "3b3aaa969bfbe432bfe7dc7753dca21e5210a53257de29918c8443e04368c2d727e1cd1bfa67236400a538158457d352a3104ece760663b63d84ffab30f8c448" },
                { "vi", "823269677312dbb8aba597e256220f219b198cb37fe79411164d15cd1005a9f4658aa4034abc6df98ed5f425074c3dfb8d362c95201a8aa576efe8b73ac690ad" },
                { "xh", "c12ef8c88b6bb53342fe87e31add3face7cf36c12bb9de687a7083fde7c29ac2c4b5c9a476f44d536f7193f2f175ceca20b851dc656ad6cc73fb9bb8eb57c439" },
                { "zh-CN", "919d5d590f9aa4bc1d3caf2cea848654cacbcaf550f55937dd51363d5de668c7c9e72f0c35b3fd2da8e49e92e7435707f982ec121289048f08f02e537673ba46" },
                { "zh-TW", "03dc03885fb06f0f7102376d1f102f48a78a57d84360e86b010f07daf1a55492ad87e1639a00c25260cea518666814709f04c5a088597c4dc38be92de9b6ddbb" }
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
