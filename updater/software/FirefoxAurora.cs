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
        private const string currentVersion = "132.0b8";

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
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8cbff03e88da43d01ce32d6c904bcc65a4508c731e4eb5a80d6ae874f68a82c2d72d5309488fa33f805da2b7e69347d9cbacd3ff729f6e824fd7a00f9c1176c6" },
                { "af", "039050b7314bd632372c70790015a25d3c92cf6504417befac46d95067494fd162eca80ab9ab6c0343484a993c6482eca99cb8b0eb4fa76e8b2e5982063bfbb1" },
                { "an", "6821f8d183f2a7d13234b878bdc0521c2d2de2e9280c0943d5d00d10602755cb44cc02c895a3e722a82c1b9d59513ca01554976bf33db608e926e114f23d9e94" },
                { "ar", "498ae9d35007e20e52c888db759b1f9ace2bc4c5cd84c3a533da0f953b0379f229b69f6f08a325099d591f19503ef74c1ffe7b87f935c539c36caa03f50df49a" },
                { "ast", "683f0f8103734c0ec2a70cf6680bee92265843f251b49e5563aad6f0a953c072672ecc3e64aa89bdf089f0de63d39dbdfbf0cd898778ec7dd048c881271e9322" },
                { "az", "ee2e46a60c1841069cf72e950c2b7888aaca99039e9f5d2faa9fdbc1d5611c2a98ca921d482612d5e6fad591524585c071d1ac06f0df61e87f971bfecae15ff2" },
                { "be", "b60ced85c79d06ad6e41d6b453c7fcc76f3efef6b2ca2ef397a75cbe933abc14076f59b95560f9289ce9d04f0d1fc7bbc45b2ffe16d25288e369a222e1633610" },
                { "bg", "ef72b8863a4b64e4a048d1b5cd4580618a6452fdb2f4b462b16db9bbe4b349c28602255679dcd6bcf4c723326b305369dd974d423004f18b8e3b33dda7123a80" },
                { "bn", "f43faa60071d6e3d017634e5e6947edc712f4d6b5a947daeac945ade0302af7ffcd84afb5c0af1ab49f48275b62eb083c981dcd8230e73f500567b7b02759005" },
                { "br", "1fd931cc35a041d5d5e896e6e819b2f7f3245c9cd79579f58015c7b8ad70cf237d35a343fac1752e428cc6bda87c05d6fd585a25fdebfce6ee49dc4dfefb5cce" },
                { "bs", "4bb38b8f1dcd7ab6ae8e75c6a4244f4bc9c2c3b9cd171a44ca7eee5727eaab403c951fce760206dc5b9d33f906b2358d4053343e8c8c0aa1bc76f43ac3d5d02e" },
                { "ca", "f4da16662e7bf72414c2f1956d8d0891784bbfc826b3b18810b63762e7d800c1cdc923d55f3ebb059c9c887dda4a5a29b2ecd21b6da0cb71470c48e6e6b38079" },
                { "cak", "0d489fdc639b5881a88fd02d9f84c6affe68049217c03a06ccd14da6b284c56f3173e4cd74fd729ed503143b629830c8df36ff8ea25547711f4fbef14f19207c" },
                { "cs", "ad60fcdcf0ef698292ed947fc5ea59f79cfc7f8016386984842b4276d5620dd1441e0da58da000b642ba4770c486d28a8f5f041704a6d40e6c622ee5293cd827" },
                { "cy", "aad0a93bd427e937277658d660cfc5831d81af3e605755bc31fa0e2afa00de235ec6ed4062c8b7ab6c425b03fbccf1f8f4b4b86db27d7fe3034fe05116a9be54" },
                { "da", "ad3ce65434715ad9347c6cbbd36986ef27ce2eba5b27186d6b19b07898d74ed3b987ed16e292e50f16e7668eca1a09dc53ad33048b207ee825cd0a9ac3c2434e" },
                { "de", "8da267c4cc61a843399bf06e0c774928e841ba3d4f636dbdb241d301bb957f46b13b91c8366fc7876c2f3a2968412ed7268c61669b9e8d806f4862a607b5068f" },
                { "dsb", "73824171443a63dae417d0332139029bd0b4891c3c6168dd28129ed8ff59bbb3a5ddbf2460c9f8df21c7c85e11172fa5e53f6be1638dce53bec1f8f9af732a6c" },
                { "el", "2d80fbe04a928ce8ae25d801a6cd23ed23901011e190e60118eaf042e42d995a05918af5e8432e587e73c4de28eba2e03a32ddfcdcb1eccdd86be5b384044e97" },
                { "en-CA", "29bfa77f64107640466861209ad47958ca65a4aaa1e26dff96f543ded534bc179d1fef32eee0f804e16c01c19975134f4b42d9b6248bebc2388ddb7d8a7daabb" },
                { "en-GB", "73597e6757759b34287ea55252764523117d347dd89e5d829fc424ac035b9473fe93b32805c425ca8c75310b477632813863a38662a5682d896646f6862f673e" },
                { "en-US", "181ca7cd04d4e9daa03176ae473dfe9092f479d8d8f04792d92c4df9e19d0f645abb8a50f0b83a1d2d0ee86240cb3ee49edac3c8321a31e8a996b7581f64c395" },
                { "eo", "18a44e9e7d771b3720b26cda3b9e627e438b9fa223e4ef43a7d946cd3db9faa0d20762bbdf437ae05d1f735be930532e44c4659c225d25865d6bc754fea514e0" },
                { "es-AR", "e818504cba7ab65a8f7bff2f5f5fad04a83c2b6011a27c8958904b4aee174f5d8c2c9381a560d8d40b649fba18d5c46fd0425fc7c792eecf22411b4ba1f2412b" },
                { "es-CL", "d4d71099527b42c2854a976e330860447bff5ba47709fcd5a8a4fb3326e3ade426903d1c8089d68ae25bf7572e9ab3a4b81113ea7d6718ce45b138d5b685cd4b" },
                { "es-ES", "eadcfdaed4f25e4947e55f68070c7580dc28e21211970fbdca19138c65b9cd4eb7db01c4eab2f8c8d8220bcdaa6016c82dda3265457fb50be86d224345a8768f" },
                { "es-MX", "1c450b9446b9e417f6c11775d4f78b006606719d721d0bb0279b6b0a6850a5f958d02dc412a7f4150c1422f7fb1be44c7803be32922f0219b46c8e6c7759d79c" },
                { "et", "2fca102c484efcde54bfa5ad505256483377a49197029ad779d49aaab8cb0f175048f81e3ccd8c47d70629a96ad927130d38d0b264916755648528b4820e68a4" },
                { "eu", "e04e8dff49999cc39fa37011d444a02ac405b2d4ea4a6c01e8dfc755bf762ad76681c96d84c267774c550f825a5f4c7027ce59a29e20dc369000ffb11cc40456" },
                { "fa", "9fb5aa8120dda22800fff0298d56b60c2853990c9dca1f1f47a29ac5a553e11ca0b5566e477c7985dc1ebfb676395ce1960624cad1648c5ffbe7be32bca296c6" },
                { "ff", "4d44d4ce1573915fd4df30e1d16fd1de4112005a4c2ba50ea95e489339fdc95f562808558a15b61f114de311c82e952c2e83f385a7335ffabc4a90d91be9e716" },
                { "fi", "4753eee1de158daf8922a8e98b71507b1c4df5759ac792bb316da1d4dbb71752be9341a62b31b4be29a3f65ee466002c418834ff6c2bb81cae7b4743a8994b38" },
                { "fr", "30d12ffb9a21d3a0e9da5b8f9f4b6128b3deb550d09b07a86cf559e55cb2fc8319287b78165086b3acf1f8d4fd557394e4e46741004507f8127a31017c2f95e3" },
                { "fur", "cd5db9071fa486df36e16af7261b7ae4508ac347b4e62e82c89d2ca3992af360580b0b3559ef22d793cdb16bf20372de5cedfee82331c69736dcf295405820a9" },
                { "fy-NL", "894ed99638c06bdf4b2e0b76c9dd9d8a08105b5e8775a3af93618e9316cb8e6d310b18ac10000e7925da8ad937679d894dd819172b075f93095ac299e39f5c93" },
                { "ga-IE", "ae3c09cdb68086991e41d80cfd4fbe3332384f0848823b82084530d0661334bb0b6713baa3122b6114fac4915c8f549b3f58a862556df5f74c218e15df3bdffa" },
                { "gd", "fe96455400d78481f81bd21b335f5bbb08d143ed22d99002534234d91690dc96c9d57cdf687c0acf8c67543a42b0d09275fc111d56a5ae33c3b8f325e6b50f29" },
                { "gl", "8d18194c76d6c8e3f6c3f5bbdd2609207095676fdcd177360e91fc26e5477544caa5e99bebf9b2e344297e39d02608c1b291bfa33e64271294490fbdf5bdf109" },
                { "gn", "58c3cb784ad09eb9536998af2d7000535cc5817f7069bf2128edde021cc7e551a285c2eaf15750990259e9acecad0f1181cea169e9e6d3d6e68ddd8c3a8700bf" },
                { "gu-IN", "2ab263f935aaa2112ecd4aa2f9ea1145e5b656e2d46e0a4392f7afa6ca4a8caa220cd25287d662c271ecc6fd52317bdec64e65674f9d976c75fe363635fd0e0e" },
                { "he", "bb6b8fcd8628c4c3d947c382958e5007df04a83fb42d5ae3d64857e9bd22f165e79762d168e2ef9c6db1b8f29cb174c3daff39b6ecb467ac672c04c8b6350a57" },
                { "hi-IN", "c7fb86a796b72a456142b3a2834a95871790e20e9704d3f7bb93480e629de0ba0303c4e0032c50cbce4011869fcd79675d6849c05fd28d3681e2670a55895d5b" },
                { "hr", "cf49791908c75c24407612616ee66323b382d6eb2525f6f367f5ed5b0322ef260af2e6ef2214972149feb717bc9162983ab36186d3eccbda227e38576db836d3" },
                { "hsb", "7b5234e0d3ecac00cea83b3b25d28010b39fa4a545df64f534bb5fe6132cb5713d2fa78601e7010c8e3c2badd4cb801b5663c5464ffef3c196bcc8c56ba9af6c" },
                { "hu", "79b8c82e2c92bb52c8324efb169cafa3755812ad06253aaf4e76e69996e77a16358eda886f87f538e718072aafe09f4f7d9a705c596f59d45a3777e76f5db318" },
                { "hy-AM", "b8a2a3841e5ed416214596fc2da0de6f6a5c95a5f0156f55122fa1504fe305fdcef5c945e9b23949825099787056a8688b2fa804a730aa1299ba1ffab06bb0a2" },
                { "ia", "64dee52531eb2ac7d55130250be3beb7651247c58691d83fa27004c3a1e68d5192fcf455eed94112b6bfadb1a738bf51465c0fe30ccd1bca53f9892647aae177" },
                { "id", "02b63711cdb8a12d9514c4fe0dfed00a05b494b0a53e29cf10ba8936354a749b47551a93b4fc131fccfd05dc6913dbc2bbed85c3459419bc9afdfd7e39e47b9c" },
                { "is", "3e222fb3277a63cf26c6b83354f0cfc68ca237ad50e203ba528564d22541234aa91c6cc49b532306f471f7742a8152c73515328ee5fe1ea46d50e10dca1021b6" },
                { "it", "169ebe5930b64aab1bf67027aa92a0adced595b01b49092806750de694c1e5095c36dcdd572187da2107f56a54c466940492776733029e58490abbd99e6ffc72" },
                { "ja", "f157329bc4d756a1772061ed0c96f46cf1cd264d0a8068f6681cd6424bd631044b398192506355afad17f676562925f159b1db40f221fcc0c3c20fa264adf828" },
                { "ka", "2900a864abd8b17b6f49d3f1d28b85cec2fc90ab68093d627673de7596e281f3c2621bacc5fea9c3969c0cdab88a5d72b0c8f72e61b3fa9644859e5ea2314986" },
                { "kab", "422689003c72014b1c26414f49faf888617cc6185dfb28d7e93b8043011358c843b08a7078476141d6cd855ba04b48225bad7a7aba303484c0ff29782b019d5b" },
                { "kk", "7ef6563f58dcf058f9525613ea1f056022785f5a65cc7d3ee4986ef2d977c166841d0846bbaf7a5664c195cc8f216eed18eab8b638123b5ad4803790e2a5c7b8" },
                { "km", "4e990e0098a592b5ac33f364cc5b129c4faadeb9ee7ccfa7a0e25c1c33945fd31ef54ddfda66588b5e278bd75d8de99131db720a9c071eb2150128687960e171" },
                { "kn", "0d0122fc19eeeaee14a56f5d1887dd51e083d5c6489cd89034494f730c3345fb66af842df2f2ae66d3cad472f5c51c543509a88bba27bcbb63b1ba5863235ba3" },
                { "ko", "60a3d2bfe59ccc45c9f77c296b3d9c9cfa1d897e122c0dd481df5cdcb1bbbbe546e4ee32f91592662306de32c9872d64a70ddf846d23040662e5c074d9f1cd15" },
                { "lij", "acfe1475c1a6a930df5f017bde2169f9ba6b3cdf0e5573edb90b2c20beaaa1f39ce00e205ece5153892adf575c3633cc106f6f824cf6cdd640efe0043a8d14d3" },
                { "lt", "c36a9adea8255059a19aeb448895b359158bfde316255a8b023f11133694db02909135fed45fed1530f197a56433e49ef84d232e715b2b15e47e80da8fe1c764" },
                { "lv", "b83ae0b299fc30e47d926759b5e6deda4d00f3798e6905ff179b009902ea925f6fe78a0733e89fc4ab1c8c7955a41b12dcf1d7689c71b5ebb8a34ea02f99dc90" },
                { "mk", "d496e47b490da63f322d0634dc8a0c0a7dc4ee640d274c44f435cd42ec4367376478bda4c0950aef1325e32b5b1df2b800be7fc0962b9f901586d243f988650d" },
                { "mr", "9244563ec042591c99ef763cc6a5de31a9433e993aff7e2339bb00a31e9d27c87418c6924c945a8ab5f16e5f62c464792ae1b87b6b74a7cdf8a79ad985e7266e" },
                { "ms", "d30572c0837e06b5af73edcbeb831e0eb6f289899c439fdf323a3749d995615185f0051a5a7a58bc9c377b16450652387c7c67285b9eb1e1ffb8072024f5c0c7" },
                { "my", "f0e3c5862667dbe8f51724f3afa0fe046f7f296a354de1039d2e8f0793ec325d1f09ab8686a7826b762fc0caf8ecf1c2ca3d2fb798e0eb7c8ce157d5450d8598" },
                { "nb-NO", "91951da4c4dd4b402212b2d77358cad3ca3f09572343ea176f3de822c7a164a3f8041f53cc444c5d03d901951331e34f65e139e1397c7eccfce526fb327d0c33" },
                { "ne-NP", "d68e8939bf45397384cd3726d0b2864b6309cad331d0ab1858bd01c22d4ae317e968a44f392a8755aa8bf0bd66924dc9205ae85f129d93a3736eb0c858afa371" },
                { "nl", "c64eba9c8ee5a10dd263f32708b398c1a92c0e8e6f90cc7af5c610e8416d1e3698cef5f46ddc5334b00bbbfcf06c8db238fdc3dffa7bd137a4fd5af04f5a8fad" },
                { "nn-NO", "d586e8b0be229842301dd7ba5a2bc2e25a6f45cb5cccd1ff1f891246fbb404ea9f882b916574e794b5223886df023b47c9c95f632e27a788dd0074643b55fd78" },
                { "oc", "bf0ecaab2c9e8f68efa0aeac051c5daee7aa631c657acde6cfcf6499f225626e7e62d83b818581b1d717a263b283d8e546f1b256abb87f138f159aee053759b8" },
                { "pa-IN", "8365893a89de9b2dbec2074a4d9eb52fe276fe26f93c951b7e6403c0279c6292dc34e1176de6e004720d8370a770ada5ffcbf35011f0da3c4446491fefd37cd8" },
                { "pl", "d4fe9d49da3a7c36cb3c08be838a360e36a828a9d7d2a6f3b5446806b49a6c0c6d04aa5b871043ff6d47b87bace8966ca5210672418e717b179ef1af43edb98f" },
                { "pt-BR", "4ea4eacccabdf30dc1db5d42b6012dd62a33587c5fa9605f216e6c15ff592b974054db5b3d46166ff0c451f4165f016b6242cfa7ac6ed47f8d5770ebeaa8ac16" },
                { "pt-PT", "276590d5d1c05aa6958c1c9087d5b637b27c02a598a6d20275c4bed456e511c3c0fb830d497bc50320d487f35d8f9ccdf7fd50ad35656e1debc6d7feb0ce4056" },
                { "rm", "5001263df472158c312a8dae9af8e8eb74d914ddb2c0ae50fba9b7456e33e04c1b28a5199d024ab99da0376a6dfe186ab5687dc441ac60d82a463264c5a29518" },
                { "ro", "91ea5342c292240e0866d3e3552132a76888b557b731474df27e98cd5e92f9303c71dd489e9977a874bc31710eb9435124f79b963a05e215cf7fa92978f5a964" },
                { "ru", "344c1a4452da0c88d60b183d7749e80e88f4e31b81b042dab56546857a199a9b2cccce8d5f71e07d39d4918cf41648c5f493f2d074d3f557ed3875db7240c395" },
                { "sat", "b04a65d9c3dd8af730fc1b95425fb413770ba8e473bdc3a410117f637f41fbeb7a57c6f9b84911b49a4fe3286c6338ee9c71a34a734f9f9bf9e64b70743c33e1" },
                { "sc", "0f4273021d19f86f2a4937b9981ca1d85b94aff5a166368752d66efba59498bae6b782608e677373c1d6b5e0add6c9e120d40a7abbc85b549092cadf9b32b2bb" },
                { "sco", "7d19519aceca06daa21b5588259e3582b6dbf28d712c05d0853d51302559ed61b975a514ab666b2995be2223d75a09755ac00a5769bb3bba31fa2e766ee3e6a1" },
                { "si", "6bfc8491731d0a1999c511cafc358e1f7bdbd826a3310d8f6be874ac5657f52469d542d25c76ea64ab61e831ce12aab933a6b21686f4b9f96a0da9084d9fedad" },
                { "sk", "ac80dae187ff0240405e016b68389ed2d0a0661375c6dcfeceeb02de18dd9fd58067a524462873c9f553912b2e4e6f0663456b4be4990c98c1c9efb6b2c48277" },
                { "skr", "aea624d75512fe833f52d66a035e0693826f015dc672b36ed01d4bf29906411e71c7544e3ca5c8da8391db34bd8d64f400680d12ada808bfccbe6b00157d9f0d" },
                { "sl", "ba5827a961ac64df26e6f174e4418c261f3a1c0bd2debe6b0b96ad86dc401629bcab9c9d10f3e2a8af8447d884c71ac7644eccf17253fd4a5d91ec58a80feee7" },
                { "son", "77cb0bca19bac174a8501d7abe0eafa46097bcf484b298840c394294fe4d66074c2aad9b7110680286ee4bee31e58d2595ddd53f06f018324448f5cae8d4e55d" },
                { "sq", "3ef58b9325b29e68a51711bbc35cc717b659e11bf4781ac944b56d0cc790a9cd00f7c52b9f4b4739000f52d68b66c58df1e200db86b92f30ba05e42a5d2ced11" },
                { "sr", "0f284bbd4d5ab150d7a2f8d937c6cbba14466c47b159d8fdd6a7052384ac53d7cd7a05b823757d5acc5425bb28dec605814f32476d4b0edd5c84a0e9d561ebc2" },
                { "sv-SE", "49681645dc50a62dc464489899dff4652801802035c3ea2a16e9f4ca2dbfbd090ff70eb7a26dcf99cff338a6a568e7917ce0bb1eed504b7c0b28f0324e1abac6" },
                { "szl", "8f392938c0489d273e4119b85f9d2380161227591959bfcae6dc2337c828e0d9bc31ebadd2f669ade0663a2e2c485587b2262909e0fca2eca8c8e3588ee6422d" },
                { "ta", "49222cda3c5b35f9ac818881e1a1abdd9bffa91867806c37cbe38e449be5d601872bf24e46d30d32eb528109ea134bb753e8b758db2f493c94b6db7dd1b664e6" },
                { "te", "c47ac0d43f17530610f8be5c4ddab11d70512dda121e1096c095f6902c9bf22d5281f56b702bcbfe514886ea3453459b74414a0aa7d6bc387a7f115ce37e890a" },
                { "tg", "2d5f6837d6e66ef307c13d115829ca795907a7fe63192c66c2a0caf978a9c9c44d8e89e50c3cf2a90eb1db827fe3eae83c47aa08716d9a7777510155eb17eb55" },
                { "th", "dc1a5835db924b3a016e529954743ede09a83cd25ddc912994446ebc1b61d1f47069e7238c3e94971f2516c7a2f47e5dbc44e55c550daffeb39bc7dafcb3239c" },
                { "tl", "25d9e99d1addf45f4275e428d83801105f8b7c82e07e55c9da063270c4086eef72a96cfbf721b45230e8cc002c082978214457017ca3c0f6b77c236feeca426e" },
                { "tr", "08dad2d9792daedf28ae365b2c5d1112c4093ac394f26b435633ae9f1aab0eb6ec0bf631ea12e90e1048dfc72d339d8a55a7ef05e68384c8998bba01fea25611" },
                { "trs", "62adad9d30542ccd5244724f8c4eef392301283a6e590772d7d3919c032d482e7c0ea8e5fde44cf85810eaa94491ef885fdb22a9c7fc728156d0a72d2de99bc1" },
                { "uk", "ade29810f855491c65fafcb78a6bec4c094365e4f24d60fa8caf76bf7f54e291823b3f8e55954992a1d0269acea2293ecdf8741132808ddbeed83f8494c213ba" },
                { "ur", "265793e3539944b782d1a643808724dd8f0b13748a7015757b3e5fed19f532a53104e045837a7c0e7a718a44b61d0b80a2a87c9c2c926b1dc9c0bb71bedb70e1" },
                { "uz", "87a07c7345b3e3b7cd67babb612a9df7c813ee02bc7816fd8e589e9ad2c07dda97e3d509fa0d0ebdf64ed044526be5337d7577bb1fa4c1a3e9679487db675774" },
                { "vi", "90ce37de36670a3429c298b572619fa260760b9a91f67450783000948fa06c7402d2376ac82a8655ca1d57ce52866049c1a86d5cdc07668a4d11e5c06c2db0e5" },
                { "xh", "8b0ba07efe8d72190dbe4f4b9cc8fc17921a651282f502e631fe9a9701536514a223f120c9a3221131a71fa56d3ca020a339eb36c8a3703dd2eee465a99cc6f1" },
                { "zh-CN", "6d37a0c6abe511576ae4fd03037ba9e84cbf884f67600b933d6c55f47f384005ea07463bb36e9cdf5fb7d8e6d779d1cc628a2ac3fa22d0b8fa48ab3c94f54821" },
                { "zh-TW", "d6300251745851e5de918b64756fdf03b6bf3246294b6ef72adf94448f7ab59a2f5da99b659fa46cc570da419404b29006af014755f3082a3874e0e3f83abd0a" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "04b7be2a9d74315254ccae8be717ac0a8d580fb19ecef0c68e7c7f0f2a71e2ee7fe1547d1e8159c495762b370e82f127c3748f81305e94a0ab61a4ebc91a231c" },
                { "af", "ae2521a993f871d5e788b2ac3247d75f7d49680b0f279965e050c954246c56b04290dcbd800d2479112c0de0d9e6cd7bf8a58ec4f17d1b0ea4ceaeed30afb6ce" },
                { "an", "374ce8aeaba47b0bba58eb524bbba68ca8590b1d2892bea2d019caeb988d87baf94107a98f86ca22f0eb33e0176e47659c0a859fed2051362e8ec353e081a7b6" },
                { "ar", "d852c00346a7237be05f1fe8d1238ee6743352d980d685270ffb1e02962c038eb2730eb697b15c2bcbf221521e18f654f948c89536a12621a62a2a4fb126548b" },
                { "ast", "9090af158b51e4bda9b3595e2c826080be6bb1ab9886b25634c29e1c86a5798e86e55f81f653d6da665fa75a40824b26788488a4ff3158fdb557da483cd05ea4" },
                { "az", "d175f8e54074c0a9d57ecdd3f7e17b56ca941087e29e2bbe32619c5e79c5b6079ef7eabed33b3a64eb72459681cb5aba610bc1391d95cae62a31a410021233e5" },
                { "be", "9c8412abb176f20a3b6ad4069e57f33904bd60e7a34cb146152e3221500c575e82031a625885bcec5ebb36524a62f4ce805e36e1d48af3356f4c68d6629116ae" },
                { "bg", "136dbd0574d16d5e74a2b000932b73a3833b2742920da96a4cafa0ddbad15e8a88963bf1e23cdde441b24c08f587ccf4c7d59f136c9af2e3c1af550ff329a87d" },
                { "bn", "d4c8be7f459a69bcde17ccfaf323831c84e1f4fad352708914a1a8118bfca3ee9a9412b6ef48caadcde875055fc40a05a0a37d5dd5e542544e8d1c006fd1b36f" },
                { "br", "e9ebdaf487a82cd4563db402e1c7e63796525ed2f89e1f0c570060fe2d08e32aceeba035eae6043b48c7152721b4ada4454af327d2b1e8eeec4bde68c88384ea" },
                { "bs", "a492c63c1f7190d4577c02deb6dfc046b8d084e5cb98147b7f902f3090fdb00ad8f7fb260b92c9b82477f4f0cb9cb046f7419b92deb3f1377d762442dccadcaf" },
                { "ca", "6cc686648c79644289de8837d43a5d4f5e353031985392bf717785bd3493b6ef6506c88ac86f75a12ab5f5ef8cc351e34845c42033d2ea2378889f3f61122cdf" },
                { "cak", "827094c206eedf9cb2f0f1f5022b7d9f6d1640180c2eb2bdfae57bc8edd110f14ed94e3f7bc6b5d28c08d418a5ff5d0247ac281efcad41f18058161d211a825e" },
                { "cs", "27c2f2fd2511ea7503935f65eb2d65916a36cad9b8e776cf7a6526a7aee0e9af88d7649ecdeb15f3876e5ca349a052ae56b500a284702db3cf79cce9c97f4f21" },
                { "cy", "a412e7e3f96d3b19517a424fe23d8b786d661cf14bf963c514024c2ecceaa77152f5ac751d6962321352a60c33f39b39cac304eac51d2b4210e2c35059c8e609" },
                { "da", "3c5c83b501bc00e9421418de02d3a675e8c83752d505f15e9c1e49f1f38faf4b16c3effdf706ea6e4a20f65a797c82f63bb851cbd6986727d84ab6de815bbfa1" },
                { "de", "9c740b84e8d95ce77d2b1ef2cbf0b7b752b798767622dcdf691aa758f621e526c57285433a7806d0c511a804a6d641281ace193404d6cdecb68cb41e27334707" },
                { "dsb", "c7c571fc14dba041d35b7d0380d3d5062825dea4fd62555c61b6bf1e1ddc250edbcfc1e071e35035929d56dbbb862d37d3c02d5fc1775d416eef3cdd6efd1102" },
                { "el", "fe5a623db26d6c02d6b9d21f85cf5670ea9e0b2b768691a7a66f4d78a6e5e6d95b9de7bff86ff0b1f6f8552dc0f4ddd91682979008620b87336f0e162becb849" },
                { "en-CA", "25e81f4014d216086ea4552e673a3f436a2e4fc0a584f47578d77a7a47b4d320ab6821a1c97b2a6631c2c04562dee2269f881f5a92e92363af37498e13cf571e" },
                { "en-GB", "13ea7d2c6cfcb2727f083631a196ba39b6ca1cb86784ba78cbf6f6ab28970fc02a067ec24985b7796cd145f82a2c5c3836200f7ec28a4620d4bed42e0e78f96b" },
                { "en-US", "ac2a88ecfde9fa29a0a035c5728554484888f10b484df8e73fa20394e9e2e13bdca99b9857917adaa8b8f57c25647ae4ec0fff3d7d0acf48d5deffba3911508e" },
                { "eo", "cdc35d62245a7eac698829851fe0b21b7882a6c113373a3613e8a2b52da08112a3db7685181a04b3fae7684e58f2970ba04c7344dc6b78d8fd4fd624aa6801e7" },
                { "es-AR", "f4735ff107a65de4e83d75b4bb9ae305fa2d23282edffbc38064fe2f49a7280cb27fac54f43f44c058cd229068b2345c69a7c44b88ceadefbc6adbfd12096cac" },
                { "es-CL", "b95a3f1d9fed8176ffff82cfb2a778da405efbfe82c919d4b6942d60d78a7865f32f126f4161018a90b7184606cafa73bca7bd6d50739fae0be990bf4daa643d" },
                { "es-ES", "a305691f857dc9c03c6223838536a8ad23f8fb75d02412390f429222709d652b07c6fe1ef1807ac45f13b6ce52d84eb56bb42b5cfdd4fa8f4f9adfe6054c4f34" },
                { "es-MX", "7c7ed83d1681154424c49c98165c5039e169ae425af4946a54cf2df776e2f10927abcb5acd32229220106ecd3db3a55bdf73121a7cc0631aa3984e2df1a6d52f" },
                { "et", "b3863a8786c27525a68a22e269fc82640a4415de04c48852df3de51e3e54d7df626fd4cf2db4e70b1d224708c4531192c4ed87bb167e7d8c4a175d0248e40fd6" },
                { "eu", "05024a892112d4e03fbc0c5be11fab8d8d3c277bf2ef8bef51d9ec5ae09ce79ccc36f1553104a8c21e2d6db6b93801a58cc8604729d340edf8ac25763f7cd9cd" },
                { "fa", "af5d4dace677130ff42ec7f76add6a89006bc32f73acec0375c61583ffea45ac269c41426b24708479eb2106f4ceda5457c424f478dcda36bb9c93eac77aca3e" },
                { "ff", "b287d130f87eacfb4993acdc4a5a9967a10ebf7281a950224b47b5d1e389ac48514f396fba262147b51b8b59a82300f5eb9538e27ffde5c7414ba401f9c21142" },
                { "fi", "588fbd5cbe2fa012c7f3760e159be52b991554513f3b8f27bc78305002cd01f145677ebf8b6d60cb6674c05182a1c791053e8683e7ac909f73f6e22cbbce24f6" },
                { "fr", "b3e550964180541885ade013804f568ed655469758eccec6b64da9733542bdc62c9269c5035b58b66a73eeabb0817d7774054d0fdbce3e6b5adc676eb2664b12" },
                { "fur", "833e211c5c30f632dd0bb889c829d6d9c1a585f4bcf584596da0de2c8d1f392f01c2cb2e7a01951a79035cf3762ebae014505c72169f5d9ef34fa92133905b00" },
                { "fy-NL", "828dd5252a6e0f0f6682a4e16c800dd468bd9bf9e35015d53574fde92bf67c9ecdfb6ec4c9284625e84c4458e9e264b0635b9c4ad330c941ee5c0085b036af47" },
                { "ga-IE", "61a3f75a1d1b5edc2ba98c0d940d5671648d3719d976b3ba63ae075ffcc55aa75082450aa762f109d1187078120c95fc44367aba00fa2e451be5351c56083b5a" },
                { "gd", "1660e62c4a11f057c0ab001f3192a01b423fb41804e6614bd0b6f1214fc313e421dc81efcbd3d2f4a57f294e7491457b3a16a0d3573f75c8a6e0ce7393fce27b" },
                { "gl", "9351ebf38791a128dabeb169c099835899971d477461e071aaf5d6298af76f377ceaf3666bb544c9774413ebbbb79715c725954a9a228efa12b6e22ffb586177" },
                { "gn", "7de6ecdb1fe8100c241105523250f1b6b4f69c0212847748a3b9b4e0b5bdd55207bee9e0e5ac051420db2573fd97fd3dbf53033e9c6f0b5a38856bf219af62ce" },
                { "gu-IN", "a6ddc068b42e1a61ffac433479411d16548c2e5f0e30de1f9438f36b38c83101cfd70435d4c756f4162b037a791c6b3bec476de8e9d14374c9fe4ac0974b9169" },
                { "he", "d6e37354c84f65442f0a668b4bca81e8e89c656e3c10d3785259cdb6bb5927d26ba1e0c4da8fafed7ef38efd05a782b3dc325f810d8407924de0ded6def0ae91" },
                { "hi-IN", "b0a5b5b6560743243b7fd422a40567d6044ca7ab1c38b6c65252bbc1471db0eba6c26b5612f74eb26cc9bfe44adda428497bd9e49303ef1045e605d7b518f494" },
                { "hr", "6038ac335e0cc415b67aa7428c66a8d99bfb9727449f8720c4c83d6a76e2660d7d545e8c4e2e3840778d9e2c8f86de2cb13438e8ce3dcbdd23af682ed3a03c8b" },
                { "hsb", "9d0f0fefecd80e3b4ac926a9ec2de2759c911064ae874142ab3a0e7eb1703f631bde8a219d7ee9130902f40dd53b4f40fa25809acc74ee59856a1478470a9ae3" },
                { "hu", "c86728de5158cbe2a709962def7097b2f31c544204cee7d133cd23bd98d442c08371c8219052a14dd482d40e151fa60044dae7d22f3534a9d7386c128fde6299" },
                { "hy-AM", "6782211c67c2fc18d5c6897eb2232cea5a40c5b7997495328f16ef9c39a8b0f2e498bd843bd092e8d434abea749e680092c30ffe9e54efa282d200b1f2d2b5e6" },
                { "ia", "baea55a91d74ff5f5303546993a0c5856d9dd73db6334f4c870178e0a5158ce894df2786e3ce39515bb2bec68eb93a979acfc90d78c6e4e9ebda297843d358f6" },
                { "id", "61ec254be9ba21db82f45dfadf6fcbc9aeb8aa9b500c8059d8f81c2e88f16fc77c0ced30b413057c632fbfa89fa02482bed8120c21b651d0ba0ebea352a78334" },
                { "is", "e37c43ab755a38fa8c20712f64e96b4189fee5b8e645f38c53f5b44eb7d34cbfde07c6c2f753191f09241b5d05e387dbd467f9321dc93289fbe1ecf5220fce29" },
                { "it", "6658a52355abff9db9468a5bb9ccc68f6c95c05a1044ecb9647f38ce17c70f76c95b519865e5c277657761bd6772073d7644a71106d6962c4d62a44ecf8bd461" },
                { "ja", "75ca5276b31f40ddc06085ad69e287c5d0cbb007fea250b7260c18abeeaffb3c739d0f721aeb1a140f5bbf8544fa1f41c2f3f7673486e4ec31377e3f5ed80345" },
                { "ka", "6030322a001e23dab4cbf54ad647c748b727214083e27e45107bbe7d912c636d261f4de70c3cbea7c457fb55c4c23df8c0416007d3f75081864e1f61c6e7a4ea" },
                { "kab", "e19f81d432cab0b8ef7f2d2636f9cd918db7f63dddae0ebaf45463b86a869984ade92ce52a2cb9bd9802f21a9468a9bfaa1535987864d3e06c4ca836fcc1aa98" },
                { "kk", "89f325fd30596ed1e88358715f99e5deb6d387bbaddd1ad687f9261c4a831a8176ba4ac08405d7e269533ebb00b57d312f9ce86f5d123876b66b2d3695f08921" },
                { "km", "fea307f29210310f3578090802f642dd743c565f03828ff729272f27e4c834f205b306acd2d4e9bd20fb92ab31007225348cdbac04da399193f35e9ac941eef6" },
                { "kn", "390063140eb3a2b1112a49ac580f45fdc3737245aa18548ac228e48bf1331689114699ca4c223eee66412d1d326b5bf8f8d94127610ff36a330484048cf33359" },
                { "ko", "ab7c2d3334222a6fb12d60951856a9ac5064564d516d02bea01fdb9d8c6e5678da0811c81c14bd056c1e19d5071a4a66f67f276aca21c8380f41bd9f1b4ac172" },
                { "lij", "4ac2b1328bf80457b8d15eb92cc740701767b2affa92b1efdb9e5d74abab2f057d5aefa75d18f6b0b1f5b1e06e45f5033dbdad94af975a5c838dc098c611c110" },
                { "lt", "0ff56080d54edd9a478b890286c5321cde0862d85ebbb262d182d630c0a5be49c9a0093d66b7ff4e584156787e0f158162f6651028452fe2f836977cbeedd1c5" },
                { "lv", "837a07be0f52ebe013a865b397d05a9bd6547757aa96f94967230aaa248869829c7cad1f66afd688810823a617aaa1bdb9953ee8661802733e7609b946195602" },
                { "mk", "b115aca90c1293ea659c71c1bb221bd8c6665e5e53155d537dd4232280bd5d78e6505b52de124403c20fdd2c34f8369d141f2c3b66aae98e079219c1a33d6458" },
                { "mr", "8200b835822ff09946d99536e208fa7a6aa373f11f016661afa35215f2f0d1faa30103908eebda46e7b8fa87c42bd87ca8915e17cea8bf7f6a2f526122f225a4" },
                { "ms", "4718dfb9b2980b344cb0672cfc7abe6004ff35958c90afbb2206c5d44fe35590a3073bdadbb3f744dbfba55a624ad6a677df7674b22dc579a541e4d37aebdc31" },
                { "my", "e7d6db049df7336f1b57f0025351ce0c11a8415f3f357a7ecef34462c9a264d58c59be396747c8c23a508158431b5ea17488fc4fb5ed51352bb1d26173e65085" },
                { "nb-NO", "59043238961c7836a72da51281b5085adc757ea69a7d649d6e4eb83da74421940500233497147f163e4e3a8153da9b76c4c79606ebeb4618ba8dfa5c4735d20c" },
                { "ne-NP", "7fad0434ece031c470ffd7226f9d7e8cbb8712eaa3618b136107324a0e6a7ab69800c3dfbc429871480b5b68022888223c0eba46061eccc598dad2ee94d8cdf5" },
                { "nl", "08206b3f4fa98243d016261d3e2d73cb8e9cb97826ba1b77d1d1f2d7f5440831c0cdf8c863ec354eb7050acff074b81615fd2c8ced294c86ef5c9341999e2963" },
                { "nn-NO", "86f5e2eaf03f9dadc12dba480aef2ef407d0d47407f6c8e3a6655abbf56c9447cce6d44bbecf4948a3edd9fb96e9a75a6cce862d3eb52944df798554112667e4" },
                { "oc", "caa7ed18ea0cde12561e96b05116b238220b76b76f212358a346a16afe703267b29e2459943efeeaaed8e8d33ee3dbf1f1ed2f4008267cfa81bfc53ab495c333" },
                { "pa-IN", "ff15276a2cc86743fd3d29239c1094236d21a9be5cc43b03600e15ce606dfe60ddf3cfce41d7b9207e89f89c0a08716449d87c311ca26825a92e322f39b4eb99" },
                { "pl", "8be079f985f16109d226b467a933f7eaa806f5a0d3e93e62cf421bae7769032e7b6b8816baf8e1d636b5743a7a3d283107fb53a48ff6b13f7d796e8d5b962ae0" },
                { "pt-BR", "c2606cf4ce1035762776b938826c1be0e845cce7c3fdaeb47b773af523f470664ca784faf2a52f38aac4043049c5fe61c3ca7a627a7cee2eca5ed1c042cb730a" },
                { "pt-PT", "b13ecf9a711b5746a20c01d65b14abadf442fd28de9c0fa613df7f1625281930d77d6c65b05a99f1c2832457f8f07588a63dd34439f7431260a70c7f21435953" },
                { "rm", "62cafef6219e22dbd3eb24373c84f8fc2770f9f3b11c9d245060d7a126f2f69fac649d12a4599e2c9dae28d580cb63602ca1f8fc4d556bc4346a0ec4a4d5901b" },
                { "ro", "86d5d145437b0ff06ad7381e54974ea09f4d962a0b1dc42eb7303a096be2b67fa1b6346a084a9f1a3ae01939a19e833fe7668e84e3a9bd8c53ed4a2903a17955" },
                { "ru", "b8821bd23c4120dac2734f3a5724a44c9bd5221bfe3fd8c94212ddb1144059887644a073c69e9d2fff83d32c4317f726a39d589d45b47a4afd724d13f540ef6f" },
                { "sat", "d5749c01a40ab2316dfaca3ac2b32e2a8d806852507011ebacdcc4c157697560e8538ce7e07bf7a9648a25b3caa0f4a1e5112adc9ac8f48d2ab66dda198928fe" },
                { "sc", "f6d73384e3a5ff03a5a41e77fad8e9371911652be2b6ca43a8941a4b98c198b5d3e69d7c921a977788e88c2b5839d527fea3ef06566e8289e0f32afffff24e46" },
                { "sco", "ba841b25179e920e55622b40ed73e12869f267fec4eb82e66a1eca9028a3a4e596ab9753ead116244a3f572618f22ed815205fc1c5a704ddbc9b5b5c9a3429f5" },
                { "si", "9c5e30ff02de173bed700eced4fe2859a33bac163c37a1d6406e18a6654365fa22d1bca5e6f8df993c311c0c815a39a9afc01c409928e9868bc8356e888911c8" },
                { "sk", "5ed83e96b549e08e9e81edbc0d133830cc1fc07c213688ec504639bc49d59879b54177d92ee27a741ae50eb268cc570883e317013b791d74dfcc9d5e7c165a8f" },
                { "skr", "48a512f6a7bb91f24c51305b8af031c11773991538acc88f0ea077bd616044409bb02a2b1ad3cd88f4e3536189fc4ebafd4a17527eb4df5e550c1bcc07e0bb68" },
                { "sl", "454a0fcc6994f95c77a811be15172adc6c5eb3b958ef0707c66c8895bf64abea31070463ee30e958e9c2e2f812d269572645d7e863dadf1765498a4dbb3dcca5" },
                { "son", "2aa1a7e3245ebe11c94527f6b3ffae39ca4313ed07e5094be77faefd5b00c64a7e43cbb36d226da48ca8cbf022e2bca0cf36a5f7bc65a88bde7af84c6ea27df4" },
                { "sq", "41aaf90c21c30a784877126f5eccd0f3cee29152cfdd5df9d52f39f057a64ffbbdc15e1aca978d1332759235d2ab0aac9d38a4c4a8cef209604d66beec773a5d" },
                { "sr", "7b5c5ad88c5fe17e44c2bd5fdd35b13caae9495797d6ed9b4baaf89a20ed5725f7d4a3930789c82a2239eb099bbaad7ff52a06b96c91a0f6f83512f65b3fff92" },
                { "sv-SE", "33915dee4f25962c1795d25a26b154763a6f1930e2747d389c0d632c9ee557232e4eec2a6043d0f37acac91fa7eb93121e26336b3c6152a0debeb88b1e4eecfa" },
                { "szl", "e7b16c3fa75c3f2fe9cf1e3f1439d95dec30d9d05cb5836b2088e60f5f5c2bafd608304c77309197b0a42c24ceecdd635036803129ddd8b9d74b0acbfef856d5" },
                { "ta", "efe27d0a657a8065f042ad5ee7b6dcc03652e12b7c54fe5d18a2142e22a82d1b6e0f1f990308cfe976bdd29120040625c9dbcff35ef4e9551ee9e33f6b5bc28f" },
                { "te", "1acce90b9b0c2da35dda4ab9050e0017d411d1ec5d00beb3a0ec98ce5b53eb336fd4e0f736e3d217aa76060e98cca446f370069da6119c9ea0d4c41e767cfaf1" },
                { "tg", "045a000ea01ad36425c0ea4b309fcce54ed75aa85efcec23f7364e35e40ccdb738d5fd3395c48bf916cef0c48de7edeaed20c0684f086c76eb1060a947bd8bc3" },
                { "th", "b65314bc441eef5cacd5de5523057d49515e6782f49f96517faf7da79f348f9028ef26d9f18d71cf0bb94245469edf5e381de5a151258360424a4620ad8e98a4" },
                { "tl", "8865c6d47653e0de3a55cd1597811bf4948777903651229614e96712e3f31623d314959139afbfccc13c6ce8391301025579bdf2049c94932b40dc27c03cd6c0" },
                { "tr", "60a2ee24f7d2c734e4e835e6991c6560394bfa11344e04e3e6b091e149a0b248a52370c7b16a2ca5cd17568169518e53f552fe251674eb79b951659ee4cf6ec9" },
                { "trs", "715aae1ac8fed143cbb23b6722af97c88e6ade91c2f5a0c686df5c20f10b522b42441bb2e8f91d2080cf1cf2ceda00fe2d0dff8438810e1e83e1f4210ea4b28e" },
                { "uk", "edd71207d604afb2b38714285bb376f983b56699d99080145205dad2ca954d011c01d35dd33b4d124d72d81d4f37403dc9d9226289519f3d3fe77597b0be2ef2" },
                { "ur", "574f766db9b74d07765bcec6e0d6f1d968a5356d5647909024bcdf81360730143adbe29e0204d39ac0f12dc9f020acb9d28a249134529da10f49af50f59864b0" },
                { "uz", "4e356bab456584db3d72bbb6d67a3466dbc51e369be32c980884bf45bd954c274cb73565ac7ff6369bee734b37de5a0abbbff3e94489f70dae6723baa5838965" },
                { "vi", "9631911775a4098fa3ff6e3d85764aaebe97878c6d5678f1a7c81959f992782fb27fc383f3388a24d7c33fd05c057ba567667a5a456f4b2d849e7dbefa927aa1" },
                { "xh", "9b042b71d6ee8913e4ff2fdb39a57e22f02bf3803b045a7564b37b4fadadf95cb0cf19e33bc3ce5f41109ef0a80109d65353de14670f9aa6078d2362b5ebaf6d" },
                { "zh-CN", "39ac047688d08eebac2d5c48ee70dd04f5e6ced64669a9ad0455550c15534e0109e261661853810d1bff406ff3235238feba56979c8aa982c0aacff78194b8dd" },
                { "zh-TW", "4f1de1bd791d99642c7bb7b3552394aa7fac4a8701250e2c0309f3b1aa60f78bd062cdeec537dd877b8f6c2066b41bce9653d521eeb642281d4217dee0f3d1cc" }
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
                    // look for lines with language code and version for 32-bit
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
                    // look for line with the correct language code and version for 64-bit
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
            return new List<string>();
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
