/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "120.0b8";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/120.0b8/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "3e548bd2748ab1441eac7fb914ef07b81b3e69be26de172b7672b48c23a5ff00b1e64b2acc226f7756e5a82cc300143a56f1711117172d4c0ff3730883bdfc64" },
                { "af", "a745e488e62c8a522d44257a229850dd36bc1cc4fbdf2b2f6d79404729355c639c1a23f9424d7038cd3a4840bd69c398a5e79a73e2166679de026496187aa8f8" },
                { "an", "2a60444dbfe56def24a91dff39f7fa4c4f47aa72f640c609d23307b50959a0eda0a078292bb5b25d909c5a94883d3cc935d8e27229927c65707b8a45c01e0c78" },
                { "ar", "fd5cb285fdea9bcd22bcfba22f8fe275dbe24b2c787d7f4f71a4add37fa3ad1827a10ff792f32638ea54e838952557cd678bce28d35f960dfbd9c6b7d83d9480" },
                { "ast", "9edf88880b18b5c8616d517aa03e70d84dc6932f56ae85221938b150a998330ab31f686272bb392fb953a34b3c80d9fe73dc398482c9b58ea6fda758aef92de3" },
                { "az", "52cc597d00148f06c30f1bfb3002dc7593d673f6c24174a5ba7d52503d0928e3bae25c58e82be4f5502705f5d7e604c32d8c9943b806709d3768aca0331e9d17" },
                { "be", "e92e641ffd15a2092c1482248a7dea52f45db3931ec167446fa53b09684d0cf5018b426ef216e9af997ec197eb173805535ff6237c79d10b7907bf7813595fe1" },
                { "bg", "89ff54217eb43df9f50d7b954238b4d954128dc28aa0736f2b0fde943d8f6401891e0075764bdbe9d135ef246650a5eafbf0f6381f9766e5eaba1ab42ceda8c7" },
                { "bn", "3b97e034c09687323478f896f41106d7fce55f3591a4f320329171149dcfbfd94e3a504c9780471ea18801df96cbcbccabc8fd1a83f1b3725e967d2a21d47a32" },
                { "br", "211a7619b63e99a937c37e22b033df0ec812fc058381d2f55615d119dce03cd57505d69269985ed644d22cc1953730a9ec7c2c03c5fe69bbbd4b91fd95bf0cad" },
                { "bs", "05df8456aa6c661fc575810e87aa85612a20a387adab8efeb0fd43de21bff5db51fddc9fe87f8ba95fe05e360e19af46b7413246b79da0c60945388eb06eba64" },
                { "ca", "8ab21ef104836a3184f0ccad42ff4aa4f267f675489b7064f68b1d05e3e5342c8f4f560efa164d62e0f5adac373224fb1c37936e40c71372f3d2163ec43e8122" },
                { "cak", "e75a07a0e7c55c70bf40016342e8743f34293ae3c6e46ea336b33aff3663b82a062a5769a27923b6d508d8a4872c271ec8090501ef4d7dce579c024e36fccc1d" },
                { "cs", "642bee8933f7a9408a6650980b14bb2d9fdb4de3343d1cac3a9821ed4b2066cdd8744e37c462af99794f2c5c59ff28c55bbe3f161bc59a5ef7068503a78540f7" },
                { "cy", "ea3ce2030c3c0e28e00db693a06e4839f374b8999460bfb645c8aa84885a03d3f3e6151ae089e805deae236c692330686368b76f18f106c20e63e189115be58c" },
                { "da", "03a9d24de9156b3208930c5d490bf63c040b8dcdd7dee50e96036505bc822684efa5d8e54d25307a34a1cd78e07a75f6dc4530b4ed88dfecb2657b8df6fd6f21" },
                { "de", "860c629d8a7c4c6b4355b3da8f633cdf218f2342aef94f404322701a5ce1fa1a67cf97854a6492e236de32b3288f7ba4fafd1c7bd62e3ea5ce04816e6d2e354b" },
                { "dsb", "edf2241605b195e1247bf92cade24d4e7b3e5a8033f1aaf56ba310484515273d5e56101f33a7ab8aa09e839033794ca8d083ce68a82a901ef53972573972aa1e" },
                { "el", "277dc3bc976cdc5a6d94760498782a3a923d00fb8caebe118fc83886e611329d133c64abf6b7e0a23a3f4b8df76becf2917e56678ecc19238f4d33c1d2a8d7ea" },
                { "en-CA", "9c7bd382330e4e5baa92cf354f020994aa38cc3b99a4008cdec09bac5be3120ec5a7eaf5eb6e73b71780855016158a80c6b81301ab039c17bbe6bd3d083144f8" },
                { "en-GB", "6a05820d55cab6f1c35c82e96a4ba2989095a8091e05350baf66a5527786068fb845af04cfe8054920ea9e2c73d7d80e778422431b97e44d71294914368984ad" },
                { "en-US", "4bdf27052cead6da88e06be9c0bcce9860c5f1c323a1aef1971751da18203181e2651a6cf2d87560ae7d060d5bf7992c5e18dc28b8d3c0dd5ece55b90b7fd2fd" },
                { "eo", "da39f7bcfcee4b7089b16138bafa791b4d9462ad1ddb498d9fbc78c7cc92bbd3d7fe6747d25f37d0342e2dadab6861340fffe3adf55282c1b59e1eb65fdb8a54" },
                { "es-AR", "ae944f12289941dd5101330dd2ebe3c306b9a6ecb304f6b96870e0085c8ea9c13e2cbeece4dbe71e45dbf505d8764c4e925870022d6db865cc8324cb56a2057b" },
                { "es-CL", "e8d171eb650b53acf23d67dd4d9bb1490509d3f39542d98f018f0f90363c02d46d3301fcd0ad3698822f8451f110f61a3db02e105fc7ab7c9a20a2bb708e3db5" },
                { "es-ES", "4d71cba80a81bacd6d5a4231c2a196d0551db15e8c36ef210efed7dba45f380601003c1390c2688241155f0fdcbd6a95f3b14dfa5dee7aa98640f0587c19d1d5" },
                { "es-MX", "a24254d8b366539bad14f4a6bc70de6dfc1d019f335cba76399eaf38cff1ba316899d2e5941248efa96284adccb4c07c3bb8732e86ab0373e1f4caa40e21e771" },
                { "et", "f2b1d79b97f2a5917599735778c39ab92aac09bcbe043c8949c90e290847ea6d2df32b681aed29220746c1e22dfe5ab7fa4a76973f9c3d25f288ef9575ead2fe" },
                { "eu", "fcd009c11e58ff6af728a72fa5981a15b5715ae724c2d3ba24eafd73d92add6b78798153a28847d37458692d79adeba07f26d5ca4670dd02d7c712203411db6f" },
                { "fa", "abb7b59b55c49de9151598fa26dc5d805a925a4007a37f96059c4888860ae3a25a56cecc3885b72540d092b78bebb51d6c72379e65d574807090dbef4df29bdd" },
                { "ff", "4e99b9cf581e14df3f7a4277add76315dc13de6e7716193bee86ffc4ec7d8710bfb77b0c6cda13d07881d4eb0a3f1cbb199e32ff4f28c772ea633ab46e274c54" },
                { "fi", "3c06f990ae382c79119b1b5804ab46a2969a7f93b9457f77bbbbb32056cbf590b74e28416d38ecd35e79f2463f703ea41300bfa178cc13437776c49c7a33feb7" },
                { "fr", "290712dc0dfd399fce89c35c98072bc14157fa712169b3a5d52a91c22321256741b375b93de1ed28efa3d742dfa1992dc3c32e41107f443b573a439839fea90a" },
                { "fur", "9218b1dd736f68247a40811a1c2a974eb833a57cbda2df2a1523ce6a1723b130602a58aa387fee54b367fdfb1c266a965096f9317eca7f36b66406c61d66a9e4" },
                { "fy-NL", "eea448faf5117dc077c46679b532c8c7990b6f2dcd2de387c400e54e3e71a3aeb5c5de928f58bf1677a230386a0dd8b86fc23a0876151a2726171e10d116d9cc" },
                { "ga-IE", "d4dccd48908e1af5d00adbf5aa70c88729beb8c3521ebbb3042662fc276cf4f978010d17d9ef649dc4bcbe184403c4a32e8f0ea60c23392918160491fb8bba06" },
                { "gd", "e1509a69699d97fe70f5792b3876b2394652d4a925f7f449040e9276bcb04eea1d7163cd5fa8b85b135535a5ea2804382b117d185ce265db55dc34376aa8e9bf" },
                { "gl", "49dff33e0c47b5ab711cdc00593807dd0a17919130e905a7e6dd99cc0090bea1f989bb24cd3f09575be432a725728330d6c7feadd1850eaac60a6ce06e31d272" },
                { "gn", "65c442f9093eb641db8de663807f3d435325d2b9a2046f441c80a137433acd38a9194499ac7909b6bf9d278b114c8bea26a4d2f879a36c1109b2182707f7a241" },
                { "gu-IN", "8650434a4afafbedfae7bc7860bd3d638d6c15d95d401ea65c87e782b36d12c9df47e85380aadd4333c720cc2949a641da63147dc689e6c68787bc4ad9bb372d" },
                { "he", "56b5e174c077127a0af05e9d020ec8f18261325885e0013081d5869bbf47f214e5862a61cebb39332e7797f553b1e8b5d74d32158f1ddb6f1799f96b64a736b2" },
                { "hi-IN", "45d28ff1f7da87bf0c78728bf95b835dc8b1e870904f4eb08dab2fc3671b4817639e683c2da350f0c3c8612cd5574ebb654e4ecf66803dc221aab7f124877a73" },
                { "hr", "d958c69559d2905589845f302335b4c55b442c89b6b303f362273a6d3f0fcf19b6ecc4079afd2f0b3d44c67c08879ef6b10e6cef8bc32ae2837ff1d8fbff56c7" },
                { "hsb", "9e992e0862cb90e72a1b4e893f7ed1e74035dcbc26649bd918226f58cee8b7e23734b2821681fc6cd167407f5af84dccdbb84159e13c0a91e4b45c7eadc42b00" },
                { "hu", "010ade25159f26d658ef9ad223cb074f970b3275161d919e032120b564ab52a08d344be222d7aa8552cb2a5a839e00d1e9ca69dea56ba894712ab872a1c8f631" },
                { "hy-AM", "69157e77a9b377597cb648e4a4101d8902e8eba09cd62ff68460891ca233acfb5ec4659459360a9671d00f0bc75175f8527e0fc944c2de99ba2478fce97ec6ad" },
                { "ia", "39ef56e5733696db5a5907570ce15edcfaac2b487e5658e9981877b4a8e7ef74949aa067088d5966572ffe18baf9ae4e687a185c7acf3cb8d7e76866515a482a" },
                { "id", "e192d7206edf5c278e3dfc80aaed63756c5a800022f9a4f2d017453f63adc5ffa54750ea30560c41680c7107068f69e81c0a348705487be39c71b6ad330bfe58" },
                { "is", "de11cfc5940aef28b2cab188ef4125e09e97403f3aaf2b2f8ff69fb7855433bd587035d5809219d34ac7bb3ffc949bf23bb85749628cf1a36a5d92952c4c2041" },
                { "it", "c88afd8227ef0f66817c0c7a596b368c40f5ce09d7510bbbc293350f3010e05776c67bc6ad62c032ff9b4d4373fa8c0a8db8062c89eb86501571af8e6bd53926" },
                { "ja", "1b00b61c422fbd60e60150e7d142212c6dca9a95c4930c3c8e657f00d7927d9ec28074a723e48bc0a00a9a1a69af8428e543b9e3cc9d73239570b2f081df4bd3" },
                { "ka", "c222232c12cd94ce3da0ab823925c3752c5133a0f06811090218c5b78e9da53dc91801d0c771beef78bbb8e99db1719929968d49b16631fc8b771bb3b86c9553" },
                { "kab", "94def58975299e98cb3b9d2be16d9d87f6e7c991afb339c8c303e85792812fe13723fea009b9a5e76cf74d5023e6c4ce6d54a64a4baa29576d1afa2d86783418" },
                { "kk", "118a2af62840efb201f5ed48fe5e14456a43927d501d6b5ad9cff3ee53daf37b40f3b544c80b8cac9d10f76afa920165946692b7c9d821604dfc7e843ba88a2f" },
                { "km", "e8a5baebaf335a521e72f3c335b4cce671ac30618b5abce48505562d3e913830c032241e2766c27f8e37feb614835f5f721578c1232aa22fc661128236e38627" },
                { "kn", "e6ed2caaef58c80bdeff8b15a966b87482a26a91b57f83731cf30a2a45057b62c58ec672456ba2cbca1c779b4d60a037ee37bc7f9ed69e6bd0ba021768a5a16c" },
                { "ko", "54f1f7d6ae8b7e95fced51c3f75f086c4e39b9f2c8ff2f65cdf2e74541c9866999240eba8894088c83fea8eb4405e8c99ce583d99ac4919072a6d840b51aad61" },
                { "lij", "83993317ef9eef3f0dbc31180fec122b491c23543863c2137cefb562453c9dc603a50de23b7cea912e8aa8fc96ab2462f104ca972cff4f278e237018a6e25381" },
                { "lt", "aac20e5cc898eb04810e09d1ab462c3e5a922d8bb4590aea2e0d3649cfa33c4c666837397a3f178a98109f2945c6404741afb0649dd159ca3e1c9c663c04c9bd" },
                { "lv", "c5f0f5d7199867a4a6e5688387df2fa61541803f6ee2832fed61e8d270947c8d5899accde7f22e02416ab69ef19930bb0542fc70b0d36eb1b50fef741d9f6618" },
                { "mk", "ebf797080a23586f7f4b2dd7dd6c11ec27abbc6a3b3d107ac2f32591b1edc3425d4fdf5cacb2a89590cc82e2a7a70ceefecfeec874fab1898d4030ecc0d25d04" },
                { "mr", "38b9e75335a3e10c209e130bd1e5340aefb1c7acc7422e30d0fae24c6e6a454be5d7fe4b7ba92b2f741f5a5c3aa7d58a90cc7b306c4ed6ab66d0022875c57c1c" },
                { "ms", "b5da86dcc3c7c398a8140176a5a5838a1f2c326f35498b5715f6bcbd9f03100abdd4c34f18ccbf1689e858412d0173be3fd9a4fcd482327845962466c7daaf9e" },
                { "my", "9a2ba488dc5dba53969344bc72e70d6caf2b1e10968fdf15a53b41004c2275ce43db4eb1aacf36a4233d4c15b23a7ed69385ffcb356e14b73115e1df8c425a2c" },
                { "nb-NO", "188481c237380cbc8c370910a6dbf13f8e5247976c506eda97c544c7dea73193ac93ffe1c2246e3244d1a12e331531a656f4469ec2af222b55c412eade114170" },
                { "ne-NP", "e3e2c479a857ed90b5e079f36620369fe19b29d30f4b8bdac3ca8bf09f9b1dcf90f985cfd3be57d2404b1dd28f378a0a46f6c4106e8d57b51bbc989ca707c4d1" },
                { "nl", "9dae07d468169acdcb43e380c6a6c7b2d474bb175003d9930d3fd1c278bc9094d7569902320bcc1ed4a9ce3de0a764d7f31f445dfb2d40efa5256f73a2d35aaa" },
                { "nn-NO", "59059ffc95bb73129a1fc46a7881910551f24c5288a6e12e64957a1a65a63ee4d0a0fbe6971d3962f108ae07e80e29a48fa1724f7b0a08fa2bf6811507992273" },
                { "oc", "18ea61633f490df074250be7b19e0d25229d721ad5d08eddd0f84ff58460dfce09b7929cc78c04e5c1fe382c8cf61c45a6e13334bfa4d13571f2c8d855f062ab" },
                { "pa-IN", "d63b63e0dd4692adcc3d12e515f6448350a60b15d77d6ea0e78b3f62aec3baeb86ca1fb420ef08bb471af67806c138e049ecbd59126b0b9e7397d8d573ef842a" },
                { "pl", "520c85a2198f4fe79893b650690894a7771dd6703bca2df30fdb520859c04c5271baf012f6fa735df379a5f97852fa2fe70ae3a283d138443ecd30e39a08513d" },
                { "pt-BR", "adfa9157fdd786b93fe397455b89a4371736e079916c37e8d309d6ec709ccb3b6185a3fa306cabb0992ae453cf2196b7ef04a6e92de5154aa948ff1e4fa0d6ec" },
                { "pt-PT", "7b077ace9af3fd0206d36b944af0584fcde4b50158045ab5d7b729ee820389df122ac00b06564d5ccbb956a16a1f4c68f6f3115cb6952b7a275a3573180a5670" },
                { "rm", "3b75d36b62bf2bf92eab94e9954f4ee3b150208afff183b5aa0c53e3f9ac71b5ad919138348af8e6b8812af746956cfe7cc66e9505e1f480721a6fe4bc25759a" },
                { "ro", "f64df6e3f4b1615b4967a9bda20fbc907f594b86939a6da817bd49f2ca18ff5bb627d177d89689557e1bf19006813ff3e8a34559e4000f798cc23915195f8d98" },
                { "ru", "35d4fbbefac0b0c87c0927192705334776f3f410dede924f896482dd312a5f9cb7a37b3e58a6a0960aa09f80c9b3e92a453cedc394923a2000307df745de869e" },
                { "sat", "05fcbabf8129f371befc5c2d829dfb08243f4dd8f3090dd96d05cf8cb646112734a953812adf831efb15c73e9ebf16f4e0722825396c624c01a0c9aaf76dae68" },
                { "sc", "660924c3f0697174b14a55d5e746c85d2a53eacd9e3e683f08209256d70d9d2987bd49be338619fdbea6ede7580c38a0b286478549ca291cf214ed8787644870" },
                { "sco", "cd9bae0d5599e85f4443077f118ddad1afe24a185b7a3ae769d231f26af90f3d34e1b8d6a95086b0923a2187e2c74ae76c7db9995a493b78c19b9e20da7f191d" },
                { "si", "47a2d9d3553aec720fceece777443b6d7bbf536f798625b600ce93185fbbc72d115e1166f6ea8faafda24b0c2726c75eed2ed0c9ecc1e75cf7b9eea66e4d2468" },
                { "sk", "3d2ef4c9710895233c2b3fc86193e5924b7b1e365909ee47e0f2f1377320bfa602f135b90a28f2bd75ba52a3136533afacf7c933ed5983c75e591dd3fa57b666" },
                { "sl", "09367a5cfcfc5fc83975a7e9904531065f20d182ffd5847d5858d0b46f2db21b9981792eaf7873b43e1e9854f85a6921b50e6cf4afee7cc54591159e83d9fa6f" },
                { "son", "635bcf9be50b19629f8ec2d3e3d50c3aa526ccb7947d73a8adc158a671b797ba7e5f1be999721de5c0d16a04eeb454620d36986c39a57bc2668f9819547404c6" },
                { "sq", "1155adcfe258b1f12f6f70515529ca0a4d3d16a19f38798c42802968d2a6b800ae72bde1a76dd09125cf6c0765a15d992b282ce60afddde77b2785807de3aca2" },
                { "sr", "17e006fc5caba441bec286f429981aa7b730ffb6b6bbbaf0986931817e4ae6a4d0e530434b20c30be700d75fdd61faa0a1579cab0d22b71350b956628f073077" },
                { "sv-SE", "3c7a2db37f7223292963894cbc7b57a5aa1234004ccdb54283a655df47d49f9248a8e677ea25c1ef1f1b710fe8e2e42c78e4404a3423cca85e5627da7ba742fc" },
                { "szl", "fca66cab59e5da7f1ccbd699888b94cf95c6976b4ba86f64faf89af25fd60e691d5410b4e085aa94e9ee1e35786850d71c6a4d685d7e02cca7fa7912a45c5b12" },
                { "ta", "73bafdef01f8d08929438ab6d0685b0f4f9a9b9e8a85095bc48ab549594ea1997cd8463d35dee115b2b9da63a26889e4ad58da0f88e48ee882026cb9eaa8b3cb" },
                { "te", "0067cdc640ec3947609d82e3b057ca0aff67ffc5036bd7ee9aa81755063e4d5b47cec6c5dbcdc79f24822b590b9b4ef4e803547f6472fb0b5caf267e310e7b0e" },
                { "tg", "ed56c6f6ad85a61af4fe5dc0bcfbe2802bfd4e1368a0b47e35dd5b20d118bf503e2aba41148032f5e54add13997e9888cc87a32a5e76f1ce3a61f0d93b383c3e" },
                { "th", "921edd4364a89b8a2eaaa2ba43d48afb6054d727dd71e1739f8f1efa69bc4f719f2f9fe01cc029de0cf211bde1505adbb8b374f555597940d845d5017bff35f0" },
                { "tl", "fabb4bde46e70e32ad55e63818f9cbeb9aecc5efe220fa8b3fa631394b74a2e78ca0b609c8c96d0b655c0b63f9fa9602e3980835e8cb905752d3185d1e8e0b57" },
                { "tr", "ea3b6db661f4ec268e4b72538065936daa7d36f907b58b79929997f479503667ed12ec70c14091f84d050565d7510f3134f40467b0d9c0586cbd6afdb025d3ea" },
                { "trs", "edecd58f049d33b70e74394d16bfb18b75fc6d21be67f41c7f64880c4399f04b3c32b105c69d3ae74290f8c86c55cc6e63720767b18b1b554bb636cada455ee1" },
                { "uk", "6523ef009d0ca3c25d382d265527729e7b5e4065622e7e9d2cfcbe39821b112e17c23da5424ed5197734b728749acaab3c52c62e1cec25d953ebacc83ee6bf92" },
                { "ur", "a3f729f0f148a80ba177aff0b10a8b2e6529dca4fd74f8433e634927ae38a83ada2fcb486cde93466393d3e754275ff7d1d50f9813050c939d65c73ca6e55506" },
                { "uz", "879c7e9dd16bdd5f5f1e3be28aa1461babd18297685ce4fb86d8fe8743fc746ebd52b65dd34b3f583e81c33ee2f7942b017923327c11032d65cf66c558e5fab9" },
                { "vi", "1376bce3ac5a529c1172908711435e8338cc617b6dce7e2e3831e9b260b7f69f2b7ae01e18c02be0f246bf98e628e6c6d2aa43dcd5580c3111db0bfe6c045d0a" },
                { "xh", "a007192d7abe45863e9d80efedf3c3d4f0ec16833577bc1e8158beca7ce9da18770dc677439a66dbf87d122165cefffbfa385780c9a695980e413442726f21fe" },
                { "zh-CN", "54ff6abe7969b4d3b0d2d6a79f095b60a48af22b1bc74b73def7d83f65197bf0683d12be3c285681ea474ff3157f653f2f8f3b13eeb82ecbd389d468c34975a0" },
                { "zh-TW", "f337ec81aebbe2df94e51b0ee4bc8b34f7828462580fcf5e1fd348543e31ac6153fcdd2fc74a9d60cee60a72e3fbc08cf003d8b95e1f3fe6e5748ce018676afc" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/120.0b8/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "786551d2d84ff07a272bb974f1432596138d3556470b93f4e09a72807bd3c818145fa2386e515bcac8ba3909e5936a6a5e2ccce37d2c4760464305e8ce87e214" },
                { "af", "ada85353d327df7d8c010148d20bda304397352327247babb10c6efaf7373b0b50e70ed16cd68a6028436c25c42efa91a515d20840ef707d413251f0e3f5eb94" },
                { "an", "70e57e9c78343960a5c9161ff004c51126fb2280c1c2a59913342c018cb8f4a6b4c973eff6a89e77d3da51822e41ce5acb5c67d928774f28cb4236fdc6b8f286" },
                { "ar", "7ff0832b40aafa52e1f5744d06a1562cd80747c9260d60d0b9f1fe2bf1d5aab83151c574a6f175903e582dcf8f646964cf4178cabfd70ceff08e7f8b86301294" },
                { "ast", "10d693b69b20a9a7b6bac59c7da286a7ec1d3324bdea006e7ecf09908f4db0446f4db92dbf803d766eec7fd14899700f0ec5302c443455b6f60342f7211d28ed" },
                { "az", "de2e3f46cc52367a3a64226ab978ce11485f620cbcc5b8326f757d62fbfed6398b78ed75e3d93d1758ce4e0b61783722c190f46228066a2eb1736eff5ab35a99" },
                { "be", "51c1010d751969f82ff592a39f8e4cb2ef062af44a14494da3c47c1c172e3d5547e34611a74f9567f00933c62da0aa7f3ef69d3f37fbe95374b45015be88f6cd" },
                { "bg", "13667b744b8a05813768b5269bbb62b707a519f38ba0e7578a4e91c25f8b620393cb4cb76b7221fa0e101510a0a731bed5fc747502c04cec0c4ff4f85d8fb2c9" },
                { "bn", "d47923325d10b774ece90833b9e601ef303fe4853e198c90ef9b97bd977fa295ad80e175b58a71d021987d29c526390ce22716eb3d1aa4e35becc4c678c53841" },
                { "br", "e610b5e062d99040717a3514adbed42cd1ed89905afcefba3655225d4d84768f25776595fd7e72d7d03836f2e847b67856381dc9a72c4df6b0b6c7e1a2429ad3" },
                { "bs", "ac7de8286439a0ef2bac8672900ce7383d7838ac9a069652a390fb0dc72b4f3d5c9f557d3040afeb968301843e685a79d17ccdbc7f0b4616f5abac32f50c6546" },
                { "ca", "791895258271c925fb324e30bedf3b530a707673ecdb3dbfe5e7dfb39d91427b8020b44597e11bc1fb8e9024807b4fe0121f0d38e87ee138d538ab30dcb5f990" },
                { "cak", "352121ffc27b4b0e884a182b683fc58d9109235666e6b6ca89b10ffe9213fafa8670425fb3030622c4d4f8d15dc0c2ee9ef8ef49e4b3e3f64715de5b360b65e3" },
                { "cs", "fdc108211d10db1e555e4d3221aaf30e21a87a2f465f0e9fef9c1b8b173f617c8ad05842c562be0295e551d4c93523107a9366390fd61151bbe53b0fc1b7691f" },
                { "cy", "c9b35163a840d2e1f99188c9dd05cf0334fd5c250a342ca84522327a8ee672d0ed140cc71a6732779b35086928b542334ce7c6d9195557ba4b1b2de47d4fe808" },
                { "da", "e86173b27a2fe62f48312f96dcd82cbb78729ee0f0284885b28e294cc061161a26c29bf2598d08a8a61cc181d9af39599858e7f2e5e67e7c4ca9e13e560a45a9" },
                { "de", "35fca76e54745c02b7dff64127f829a326933c17e649f7bcca889f4ac3db5e0eb05237491968db94ad1ce09c8cb3f23e0ca4a0658ab89030e740b7f7fcfd2d9e" },
                { "dsb", "dc85db5ca3f1f2cd6e98baf50a657ebd4d7b69c2600dc1d7b6f1209a61cccdc91dd337242d7fb431c416a4922782fb6c944fe9d27db8d813bf7d1ddd05041844" },
                { "el", "d468115a444d69dac3d05275eb072b03a1d3e8a732e50d44d694f8872e4fcaa2d386a4cf96793c20c1838ff5637cea5e3dbdbd314d8d6cb0e14b8e8e232d1245" },
                { "en-CA", "7b9939dac25ba9c716294870877b60d022d59e0676fbeb3286527b6a10f2434d9f337f768dd4602023ebf40e3d125b70f7672ae4c4911df8744ef2e8bdf87c23" },
                { "en-GB", "6cface3bbaa3245f66e2a58603ae9afa303988d8833fcd7b315b8fb7c349f71dea3fbf074e60a87557c7b10e737655922cabfc8fbf65bc4fa41527eb5ca15baf" },
                { "en-US", "1fa0b9141972379202cb770ae205e5aca30510a63a7c3c3718be5eda7c56e635f846eead22264eba34af0e07ed4da1495c384937d87758518915813ff700a1a1" },
                { "eo", "9505d108f8060755b0444ef3e9a269fa9219c085f3906db57d772367421a6c2cc11b013e4e5274dfc779766e04554832493013ede86b432e02b4b700a2b1dcc7" },
                { "es-AR", "b6cfd5b386c96f89891bf55acc863ff9f699affcfba1233421d4874c952c6cee08b93396ebd86f1ed1f02e981a8a3021a58cb132786955890876b088c6aaf90a" },
                { "es-CL", "65fbaefd51a9ad34ebed926783d48125cf7ba89ccd0393bb5832f776eb4efa62784baacc527484b80b65cb86921b7bc89b59646023d32ad8e74ad1209f32216f" },
                { "es-ES", "f52370a167c5e57211897a9e0c8c6bf2a457ba4c680f4d03a922c71dc7c78120f81d6b1bec3e3b5301f5fb6f52784f9796ce23d9382355b6408338b993939681" },
                { "es-MX", "1ca617c03b7b732f47420273a1128c7bb01994b9949717af700b9e57809e2a0f9a09894100c630ff2241f8f3859a9e110d2a281152bb8342c9e7da383f02df05" },
                { "et", "2fc4bd8faffbd93cb71a7ae32dfda36a694f5974f7d10369d9d076bdecad4e8d26c418895da5a1a02d0e341477a992825509839b9a76be1cd218c3eb06c468a2" },
                { "eu", "5adf7660a9ce15fd602b9871ee41792038f45e1357ae392339e72760779c86a194ff179a37e6b2727eb4f641d959eec8bc736c9b7cf0df30bee7c44336cd1eca" },
                { "fa", "5eaf38c0e6f6746ae953cb17c91b0459465758f19b4d514592c52eafbd21f6d5b0b8f9ce4aa5975f256ab7c2358b2129abaa581bcabf4d30e362acce330e5791" },
                { "ff", "704261bcfd3f3b1cd6669643b5eb0197a5127c4a9ac30455448bc7e48d2c1453e2040b4c620ade66bcbb8364f715d8647682b2d83c637ca0d0291dae9d58ca20" },
                { "fi", "64167f5b9fec21924bae7df067d6c6de6730d7ebb036a42936186f1852391ed07b36f7b3007f3ae48246b72d5fd3dac9a61be6270b864b108627122b8c79c30f" },
                { "fr", "18de86c731fe87a3d6d9fa3cbd3a8a4cc037782b217e10b4202d635c2393b69c1310ab0c044f5fd48bff13deb1eb42ee8029c26c28ca155179679fd16c71bec2" },
                { "fur", "57054087069355d60b5bf21183559a1cb8a714bc1d4839db042515793c0d666dbf92148d5471cf79d36c17494e1357cb76937d17316b124a9daf7e78084c73fb" },
                { "fy-NL", "1ccb426f468d646f8cd7f777268bd20876a8e272401bba774243907355d15aa21f2327d91d10fc9687d65b1c8cc3bd2ac57b2121b9bc5db053cf4a197bbf15d0" },
                { "ga-IE", "a4fd0e7f3984d9c0b5f00213ae4c9ea4a693e942031d1d4d39d60aac46c129a8d434265d4e921cb7e5a80072d16888d6711fb50ed0b215be584ccfe4130afd0c" },
                { "gd", "6f8a5228bb30bd5e17722ec5195f373bffc373317ee5662a1ef8f1cae56cdd7b5a6f1c451069607e6b9b7acdff8d95b04155cb7323e79f910ee73f8e855719d3" },
                { "gl", "61c7e75e7250399fa334668d4b47e1ef01c6448662f8d7c0e6ae6e5818f13553c46909ff279ec47afc56c375f22b9331d096146874eea9f73bf386c4719b4e28" },
                { "gn", "8df8453f4e67c00b274b4c919d58a6b119aa3a85a8ba7048d21c05ac78cf6f09ae36cd4d82e17ba524e051ab2b843b7223d2ce59724b44fe2c33c595c552c9fc" },
                { "gu-IN", "b048086b7dc08d289095018b292da23c43e4f9a5d67427b1fdf12e88711125a49103c19526fa810847f241a7f9879fa2520c13b70f4dd1d0f6406703703f32ba" },
                { "he", "f767cb80911d5df58a10c1b7b90f58a9148a16db23a60248c746b949fb0321cd7b134dbf6870b21038a089a72210b1768b6dcfad66e28802de5489aa0fb7325a" },
                { "hi-IN", "4cb3c2e33de1baea278706c5473779a5bb02b9682ebb368667f054b96bcf38ebf9a477fbf08860d88afcb5f85178631eefeb07abd75dbb3855383c3806ab2b95" },
                { "hr", "87ae1c3be369e9179b20719453a5ce58585cfb10be7ad73e997df2af5c4f208e87c22665402849eb13b78ebce2bdc3c902316e8bba499afa526d6fc52ee08927" },
                { "hsb", "8435d910fa81eb833cf45bae18f8f79b33ef086cc14276e00743cb7e463b00bb715ae93d49cf550769243a18b5a290fb018f79d0e90a92bdc0fb958b20b19bc9" },
                { "hu", "a0d4858656ce793ed51e9b3a9622ed68647e094873eb4cc8ac5d571ccb8bf0833319572ca7a0a74401a8b4ec311a90ebb332b188364bd47552884bffced3284b" },
                { "hy-AM", "d3cea43984836e4d91156573e326d0b31e3dff91ca679de1ea535428dc2dab8e0f53d038932a1e44237ad9df5c0c9a2f07e72bf5c0f765a6615699b7b0e3c88e" },
                { "ia", "c516101cace713ba8065236c3237febd4c9666dd22b35bcda945091547601e7ebf3d8c93e83b6ef86aa092bc1e16f2cff85a07881469014a59e42c8ddebf1d7e" },
                { "id", "ff7559ed1e6bc9a3afb9e01c2ffb955b78d3e9e0c2fccc623443d7b57a3c1224164963e8907710c97b2bb12e268de31365ef760277d74dce62902c98522373d0" },
                { "is", "a051fc5ebbc6a34bee5723faf2063def74189aac9854b1121f8d77f8f2490ebd8165eda61253a846c43e9275ecd1696ac83d35e99f5eb3d03499b265619f140c" },
                { "it", "13a9466c515f00e252ac96d3c5de86dfa448206c1a693e4964baadb250203979a1da52e4078bdb358624e697e03d2bb591cedf45a85437023531308a42878e28" },
                { "ja", "f8da42c24734a2108cd44ae2000c3a2baf514a39b33618b75ba007c936135e3d557b2d8c82e9b83185ed0911ced7d0f3d82f9552e6bf3e926ca30d2846d94169" },
                { "ka", "378b2709238cc50b53e80e12a8a5af10454af3c7c3ebcf2d2c54347525ae06be86cde3042e1f84aee7aece82c0ba84235f787f0c88e8ece446a4cb8f224e84ab" },
                { "kab", "53bdde3df05f7005a8f9a074fd25388983bd1cb16e8fb7ee497378d5243127ecd54c4b72744cd4f168e211f0d6feb1f6f4ef79d3d8f6cb1eb65285afd56c13b9" },
                { "kk", "60c0d225094ef2b4a6dc4d2f2bbed17c1ca6f9f0bfaeadaf575edbd63615a2bbaa64e1dbfced8dfb276e93bcad8900119865f4ddc72e561e2c83f157e8df8cac" },
                { "km", "ab14adb7e35886fc3fc9eb515aa9d4a8430c74d3145b812119a44b1f987fbe0430243aaa7bbdd28b087c0ca826f01239f7e1362f16136683696e420e42aeb94e" },
                { "kn", "40eaf9775c8d2f241bb11301e8cb925f0897fe5c3f5caf476fcf8e8df0e726c90184855cc6babf7d031d4a906914a049ab6540af374b478be346b00c6fdd2aef" },
                { "ko", "92fb0072bf4b7dea3aa1a64a06112ba675268d8f0c3eb4ef1f9797a3421c3728e042345ae2e1ba0f5300295e7acd9640656ea5f5abc8fc25db013ed7274f0542" },
                { "lij", "fac03008271feb3ac8b4d8f0980f3f9fe380d906c23c0b4f27234a43e3be91c976bf530b44620b9da481ca1d38369312ac8a5f19c1d772f4202cb3b617eed18f" },
                { "lt", "9f27a62060961df515949dc0cb09523f0688b6c8a7cef05727c2f72da84e8d8334f559c74db1baebdef014e061172c03648a17c5d5e82c46c0cb52cc9acd35c7" },
                { "lv", "096202b99b2e61e7f6c6b3788d7c54c568a0e1e2a1bac9bc9c86a943a7b28736d0beea49dc9f58c6ca9bfed1fa0899ab712b6cdc391372ba686f90d1f6d148a8" },
                { "mk", "667420ea212b7f0e138d02a8a2904fedb234c45ef08e5640bb1abde81c870906fde5c84e3a8cd21c95d0adbe87662b7257fc6705391b0f09458b09c725decb37" },
                { "mr", "946c0fc6f9bc59b7ee79edab85f1dd2583c50a937bdf817e46f78d794d28a7b343dab51aa12761fc668f5843485f82f1e54ff30620028d33de95d5b036ff5684" },
                { "ms", "01c4e023b8c81b35d62391b752acb6b1d4f4a6c23f1bf3955779a8ff9d13e66d529c159296a6f86d9001013c92f1de9b9e1097a0114ba508a500bb022de70ebd" },
                { "my", "172b2b023a71b2378d601df7701e2d6aff28b17abde6d624da78cf7fef50471584e180393a9fcc6f09ddc468e58d5ac3532e5e0a241cc249a23780a36b1efdd3" },
                { "nb-NO", "051d1ef04fa6e95801fab19dc93db7e565cd971eedca035da209537e5ecfd213b756c8e47963e28387ca65da77bc5395bcf0747b5ca5c8f138f2ca7b1da1fbed" },
                { "ne-NP", "4b85d9adb9e22bc5eb55942a201ca17ee69b6f828eb1947a82cab83f0ae9bd9aa7b486f36deb990c93bff0b28a79ec125d3f007e8bf3fc2e5002cab8254ad63f" },
                { "nl", "b7fdaa002cfde97252974e62f6a763b1daf21dce3f58f6d5d364ed95184adea167a0483c01b2b6cdadce2a3596fed1986db26085025acdc8055efd8e7583d195" },
                { "nn-NO", "dc092614fffd5a56c863d17e0b3d4c55b1756eeb0b078df45e11e1810fa48bd9510c97cc6390ca9998cd98859a6d1005ac7e567750a5cc172e04756467ce159b" },
                { "oc", "4075451cd9fd042a6e7b8448a8c773c946e3dec49e1ccdf68c1446082fdd298d8e10c7ea96515083b0b92e65a6a0d1da3e589f2eb0afddf0ba6f579dc6879b4f" },
                { "pa-IN", "fe9b3ced02ec7f5cb95659f465a8c27236288ff1288ff0beeed87184c32a171c540842b212daadfdcce510394215db4b3227a0e78fa0c56f4c6901489b241f60" },
                { "pl", "4aa0e5f6e907dfa0974929f721371125cde3c46f51cd24e74b6edc7710c6e7b8b46384a1d72b0be7a7b5e5a4923c7680183e311f37a9ec767509e1a72ff3c1bc" },
                { "pt-BR", "98b81ad35b508aa31a5319c9d4d00d67e1406d121fb5da492e8567416bd70ad7e6f44062c6edbcd6e3d4800801e9877d2811ab7cc5215620952ed69edbec02ab" },
                { "pt-PT", "7e64161f1265886e055b2ccebf73297a24aea49f5973836d37ef793cbaec05ced0070c3d2895f73b0d91a8a26efd17abbaf2174e5ce00fb6f9417d9c72fcd0b3" },
                { "rm", "6ec0f5e0b62fd11bb4f2cd0f338b6843476f8470c37308fd6865763ddcf27e98e37ef1765c2c14aa5273e4bf7debf02d40a28302a09c68c95553dd4f1c5f1751" },
                { "ro", "081a61a676d375e805b4eb5e097678ab3777a3a701e8fa51bafce4f30f64378cec8334db689a54c929b1c86f719ae5363bcc17d004e75016a322f63272525bf2" },
                { "ru", "03ad6d303b19b0d3d8ea16df90e99c3fa8e345dc3d6b233601ee28f327bf8b4524913817d9ca5c5a0a9470ca493ebcabde9401e889117ea4fb8ecfca261ff0e7" },
                { "sat", "baff304df8abdaa361da8a51247787ac69b4ae057fc3b241edd6f23f130af3fcee7e72aa3db7c239dfb2ef2c0571dc5b8394db6afdf5a04d7c23c2bfa57342c0" },
                { "sc", "9d67e48eff204919ccb87cee79b190a974ccb529373cf8e41dd08064d5ca9aa6ffc00f0c88a419f5f4f324e6c16ea3df0de3db61113bc779d65aafc13f1284fd" },
                { "sco", "0fe7aa8fd4e0647667d097e1203ea9a0bd708dbb7db72fff067d12c7e66acf33c6b11f6828f17093ab20b0e5695f96cae63d7f534f04750a48bba8093b4384c5" },
                { "si", "8a030265c6042066fe133e5d21c73e68fcec045abe027821cfea0d57e4c8ecdfae04d65d5298346fb6611037a78b2eddd8e5c7ee2ca21cb728ffbca0fa287208" },
                { "sk", "157276bb03d2aa45ebedaa46f5c98715e606fd4d460ade43ad948bfca5caa9a8934f612b06357733eb228c05a54f6a099c50120906f6e174eee68c82a028c6a6" },
                { "sl", "cae8a1a7f6f032c56299c1e39a218b1d6a5b87b9663f830e7dae1b5cc263e30d39953c4780053a0a456d2576de575e12964a420fd45f68e8440feb73d94fefdb" },
                { "son", "7640848c1d6474ee23afaf56fab1c2dbe069d34e905665fdee140cf2add9b2ffac7ef93119dd95f743fe295f19f99f9a57084f338450809664d0860af8cb5a4b" },
                { "sq", "01233d04a589be5d323b1c02206cde587b0150a1a76821917c2f4a257b29deed1150b389ed4e62268e19714bd7c755beb72a59e5e12b4e2e235fd1d9cc269a98" },
                { "sr", "61a88f9bd68ea750e4a042ab40d7c11b4a6158c4cd4a1f31e0c9fb6558ab872685cec8d4b616241700d1b763a84ff1056fd22f8ea6f2b1c7d6e0269319f097ca" },
                { "sv-SE", "7bd0fdd1339fa2fcfee9a55484de83859a7033aea50db9015963649bc89756eca9ebc34fbf8bbbd7661607e82edb55d66808b65d1700120b1df8d581818fee08" },
                { "szl", "fc7f13da17ddded73fcc4c4fdd6ee20c9da98f40b590911c23411092cabce84b48867dff300359596e487ac68b0707aaacaf658abb91226f89038304ae5ac31c" },
                { "ta", "0d1a726484414f81d659a3d0d1027066b105f84f8e07387e52342cef9a85e486509bcc6051887c2988a0c268b7b0d561d5d82f33e3d2d008cd301b758c10f64f" },
                { "te", "f803ba6f84fda533bec5a70c8edf789f68dfb001a43d2ee9191602c6ab0381e95d8da8af9ef72cb91074274c3a67ed3dbf4ee3a256d95d0b714253cdbf3d6d5c" },
                { "tg", "de8adbbca7c65b6fc6e3fab05950c7b48830c993f20b4b684c441b324d086ba442f4d588758e77beb3343c268e212df6ec32620acc4189abc56ab66d1036fc51" },
                { "th", "b985f3fec3ed20530a4ebd8935c29c281eac3eaf23050fac412514965224a13b138d3b11255635525c4577649fcbeaa95420d5d1ff46e7d28f5306b8c215a7e6" },
                { "tl", "8fd4a4e09a8bf0fac7a8ad7c533a2fcf599011539f3e08881ad3a1aa9dc7460f18e3f96cfd45dfa9b0f9a3ab769a3357b511de01fcab5ea66913dcd71cd19f57" },
                { "tr", "bef8107ed2f478da211e5e17a940ea717187cc365ec17d2215102dc7e928f53ec3e3d134d78a89df3e5f94e6953bead6004411e50bfc4a946bd3658bdb205d81" },
                { "trs", "e2dc23f74b19e4b959e173dcd8f482755d77ee63954df7eb0f7c14bf8f98c1e9bea3d108f10eb364b6e1aa7fe254e91928773561a862a60afcdf76e7f7735628" },
                { "uk", "dcd37829ef982ba91ed4507f610b742d514406f92c5b41b129f1fa008b1479fb221b30d1cb36173d01d1de68901d4c930bcfc0247e774f2ac5bd4d2a175a136d" },
                { "ur", "2249ee9a92a91c3b9430a4a878d5a9250e52a84e0cf43ee124b86d87345061e00a3493be1228ab077f4d27a09762d71b01109a0bb82121a434478eeb0967608f" },
                { "uz", "2203c46852fcdc6996ae9cbda43ac4d8efcedb6806728d7f42571e65a21816e9bbc590e8b344a6270ec6e6557c81e352dc4a55b375ae33a4ed0456382af9f7d2" },
                { "vi", "086db5cf6ce166459a1d7d3953c69a6bd9e37ba588ff1167c39ab7c09c55446304ef8ac23cf92fa206bd648851b0f18fa7c52720ce1f0e9dfbffe608c8b4dab5" },
                { "xh", "d6c1d6d80578a9dbb2707a2f367921695ca9adc77339869d79a42c0b2e4edecfac6d0febd6320ca55f36a8c78143e5f739333357dde1f72d6e422643fdeee29a" },
                { "zh-CN", "6779666096a63bb1ab9cc3f44296fa9b198ad589914ef39523557b081703f1f85801772ee39d3ef9b9db7005af5e2e4ed921bb6ac3b4e1acbf408bd36a6f1a41" },
                { "zh-TW", "a3258e3234ab9f75fc11ddcc11ce29979b421b8b1ac745b01f45aeaa0ff9ac136b44d638761e76142aadd2fa5fef49fdd1d3ddb0010eb34b3e3f8787daeb4a6b" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
