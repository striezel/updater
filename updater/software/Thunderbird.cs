/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "2ca3d7a4c1f934b809ac68e0516ad1a66cab1ee1cdee01dd7e50acc8dc190471602883ab31e50d76de781c113a1d77353e0eee14f215a1e2fe071031f62912d7" },
                { "ar", "5a627d108714f8ffa8172c4ce60655e9de2916661952310c69cb1b27f51608987419419bf74bb29510454ebf8f5969a9e1ccabee6132d607e0ca2ef6ec906f67" },
                { "ast", "4de85da39b59a67b905cb3b14cc45e90aa55429178737818c69c11daf78ecb4ff6416cebbd2f1fd608ab00624607cba68b7f1ca37dad5a22bf6d3eb582a6cced" },
                { "be", "82ecc32920bd3cfe700afb8b1d8bc562207e7494bb818282190248a8b56d26d5debc3b5affeb669ba23ba0cc13c1329855fc686f474c444645be818e6d4aa322" },
                { "bg", "8856dbc307ed7ff90f2e7ae6e762156a4feb5541fc204e6bb2e4d1545b3e96f2fba4a432b1886ec71e9d72213cd51d62cc295d7b2beb0c38c9efb8652eeb056c" },
                { "br", "0356d651194d87d47702c3acc880590693968dac594500fff6a192e6c49752071f0d9ecfed5b6b3d6de181e4e29877c245776fd00e8dd5be99242bcf5c8b3806" },
                { "ca", "ae428299997acd678f4878e07a2e24f76434dd2a449fb3f22ac7418102fc9e9ee1cdc085c1a9e3c7e88d8e0bb5b764bb53315a57f7e3b95eee51dec0f03c1442" },
                { "cak", "5f7fd6f80dfe4cd54f92be293ae81dcc0a737471624b58f8445ccf42b8484c7903bedceb59f32c7b16a38652dfa714fe6f001fc60afffaaacfe3286c4f4f1b1d" },
                { "cs", "940339bfa283b50610dec499537f73b53d20f8e7b7f95110336dd0187687e8be80988054808d1643c778c618f873f1ed1547f9e252f80e169bce0f262b3f5ed7" },
                { "cy", "e346d08515102c7c2fa9ee4532b74f790ab52ade3fe5047d043df4926213765e88098685a36a95fb64acdb489db3ae7f8c21cb386f6680958b116f67b42e8b79" },
                { "da", "31adbf6d108805f9cca7d490f3e107d76f978d1c3ad37bf241a32c07f7e8f3998534d02184c3b32718924baf39c8ab3618817d5d9863555474e3df0f493ff6da" },
                { "de", "7a31e23c3e5eddbb689acfa754dcaec86bbb29d0f9b89913fabbbfd3d3d855b39d5958eb72109943745d66b198054d1ce07fea3d730d1cb211131fe9da5edc6a" },
                { "dsb", "7a7da767025e89f1958d90888458808e09869d912448db469d30c42b728394f7f65ce641cfe8b98edd8c28746fbab7a62a42764fbc947d320449cdf8dae6f0a2" },
                { "el", "8dc979c0da8797ba934960807d77052a646217ae3120bf3ce4a888f198861e3cc06261975f9586711ed656d90f7f8a0f4feeaf825798ce5f2fc516ba6053fc00" },
                { "en-CA", "4cc118fd0221ea0eb7a60ea268d0b85a4dfeabbfd208007bf751758cf6b45b00ad42cbb93216d40866fde9198b218cedd69b9b83677c296933ddf322a52e8c9d" },
                { "en-GB", "efb6753c015635dde015f1ef813f6a1ae3a8f32de6566feba07e150d0cc7e33dcbbba7384ce198314ea8a7582db260ff4d003b9525f27622ea49834507bc03da" },
                { "en-US", "b50afe8eb9ea8209b6923aa08f573823372414bf2220b708017feafc6b78cf9fb5385b5a539c97d0b0600d90a154145d20716313011a468731938a840dee316c" },
                { "es-AR", "fa9b26334569caadfb1ecd35fac95f250d485ea9c596766da1066afcfaedda2880276f075c4f5399e6a2520da642006be0691639aab7c7abded03713438688ec" },
                { "es-ES", "19a39747ff9d8695c5825b9330b232fc744e539159a866cdcffda964fd920cc9465dcf6d22efeb87cef29aecdb7d7fb4265d1ae0d31fa40d8264dbcf232d7ffb" },
                { "es-MX", "2f7ffdb471e803207000a43ef510cf8c64128083a05a895207afb2faaa7837e06eca18ad794ccc5b1925dc930c1dfc95ace32e58509e1343858f42e105b085b8" },
                { "et", "f2363792d4966c6ff3d6136066d1b2b3dc0b93b7976cb6a2d7c407c2ea59ae8857c9892f21ea7dfe6251830b9579fdd88162c9a9cba877786665ca0448a822d2" },
                { "eu", "3bec01220cda39450375c4ad308861f28424fcdbbe20d4349c2bcb1fe54866d38511e98a5973ca20da36f929e5f9ee614b154265391c2406a7c4b31b86014227" },
                { "fi", "472b1f4dae4fef2873f21c08a9df6bc8cce6bfce74d80e7374396485f4259d3ac5da1b60b54a275289b6b4c52e1d9b399e0167dd16bcbc3535c06354083a700c" },
                { "fr", "2f93144a48a2b80017da67f36985e6f2c6df69b9afc96eee7b04c5d970b93f6b6328368399adcd64ddfe601288121fe2dd2de23192817d7d4a5e67dbe970cbd6" },
                { "fy-NL", "1cdc177e99152be4151068b7d33022dd97a915e88e7de0e48432965044af895c9ec7c1c06d349933e1b2dcf5c16fa79fd21e523373736b49eeca1f366eaa8bf6" },
                { "ga-IE", "23cca7f582465ffc80f1770f27eed733f7986f7fbe7caf535dc589f5df49be657dde990c25153bcb905c3a8df40fe611195a257f58b8fb72790e35d8d736d147" },
                { "gd", "88e8a902a89896f1ba5b7f69b31bde8f3f14273862a45a55ae0ac25783764526fdea6d476b4f90567733d16e31c9724a2731d9f9d8fbdd99970b8a6003a2684e" },
                { "gl", "b3b2d1dff5f55445c695c33cd73c5e6077db2541195988709c9de29004d04af050af186cefd3ea60c0e1a1fbb6da35622c19040e792e1e53d5ab63a6de3572de" },
                { "he", "4ac6c32ed190ee97789e41742e4caefeaa2b001d231095d34b236e444c17eeb6ef8cc327335ffd86b02ee368540da6b5d8c2e5e2ed56b2275cc4928350769e70" },
                { "hr", "c4c06ed90978206fb31fcae64e43450eb34803722cbd695ceab5b15d3ddfca5dda8bf55273a4a16d07308bf0da031f6c1c6c32f8c51e5d2aad02d4fea6c55e72" },
                { "hsb", "e43eae8aac7d3fb38260e9bfa7972c0934f83284e96822290acd342c564161ff1044e6221dadb8ce1bfe3c44e7eefdcb400c66999f8e08317051d900fb9bf25d" },
                { "hu", "427c643e1af139e70c5000eed787cc3d5e25e87ae622a547f12acc55009586e52159489ecd93c7e3a9b704cab59913228d01a454fa41b81ea48a7840e94f9408" },
                { "hy-AM", "aa3f410eb07985a3846e1e806afbd18e95ce88068c761c9184bc1a93638d68d62b0aa4ca0d4519ad62a842b0c0ee20cecedee734dad34309e45f031c9b0eec57" },
                { "id", "5336c953deb4b69f998a5474827a80848c1a7adcc6ab9b415703d4ce9200df3758ad14fe2753e1d2c1db717212fd3aae35309431a6b91fb84b525aa25e421bcb" },
                { "is", "6fe920006deba01113565c8588254bf58a457b02d98e7e6df1a1071886ad82f6f39d01b10a64a885c0134a61735017c3d7433488685c2fa7038f6092c9ffcf9f" },
                { "it", "eee1d08d131a68854810b843568529c29c9052e81fe974f94f25d8d3db00805682e212fb5126637e050f64a55f9328417b6f427ea75fd1053fc748038db2d718" },
                { "ja", "48e336b35e77d8a32e3d9d6b2496ecfa323e212c8b4c6a17c0194a02cdb5dc7af5bf37f8b573e23367588d3df980d63f07ef537ecc32c86e5e34f4aa4de8469c" },
                { "ka", "a6116a324a5f22c5d8f2671ca403421273e0d2519224a162ebafa9d13eb5ab57bee271addda417d3392f168fc4d7bcbafd41bd055b532e7e4eba21d19fa161b0" },
                { "kab", "33ea7747312dbb2c542c703bd5a9bf80a67900f5dca6f884fdf367c7c783f9a39e5f998c57e6a60edfab549957fd99c327b1c843bc63834facda72f93a95329d" },
                { "kk", "2f90a24c49232019a0193731472d43491b9e9f397f2163a3d963f003e036f4f535036e55fb71dd7303a25085eee1dcddb54e96ca44283469177c0458ec4a657d" },
                { "ko", "d4f1276c617fc98aed1a3467c5dd0f1fe2ab40c013c3ae72c42277f39a2ee0b0c6ea6abc1fe10079b45aa3542dc557361fe9a331b4b1dead54a488b8e3b2c75d" },
                { "lt", "4abd20fc897d502606810759503749853d8be32dfbcf73640ae1b47e4c08c68be9f4fe5d70efef4066cf6264851d56642acd6cb88df676022fc307f663f6b18f" },
                { "lv", "4bc070c2f10a115eae504c9314d1839e1c05bff7557011224295602bb05ebe6f9d3b4b78f5efe16da52d5c3c54e1a0f1c3085bccae5ebb729e54b1e3b280fb98" },
                { "ms", "3d7b27c9015e7a1b8005609c67fcbd7762541c56b57e43c5810a6bcd2104521d484d334f14a01f085e97499848368f0ff86b03dedd9d8522093600f493c14760" },
                { "nb-NO", "e299e27ba8e9f11a12c5363a8c6cf910e98d3cb4eb04cce8e107029b4f437e1a05a47592e33620a9e9987dfe9036ca1ccf23a50c434b65e08d4cc1ffd32df536" },
                { "nl", "8f6e5f8f739e5e703e4e3cdd4498fa9154e8382d9d2b333726432dc4f7b777c68f4bd47aa9671ae16a88e8398bf5c206d6ccde99c397fb58c27076d2ea7528e5" },
                { "nn-NO", "34eafec85043c79ba9f064ffa61577fecc97f7d57883bc7b59483cf846a51dfae0b3ff8738b29d078cac82a6fb25f6f438f116428f60277d7b32504be719579b" },
                { "pa-IN", "91397687ff8fac9490d974726f087878504f37efdd901aa0e3f80747e50123dcd51038880e758d6bbb5fb51e047110978d38e396f7fb31ec7640815b3cf0f975" },
                { "pl", "97695d0856cfbde320fb6c252a6595adbbb1e966a4849135870c99357b820bd7a9eb292a5ad5741049ed8a92f4c265a4a35b495945535fb85e841dc81d54d8da" },
                { "pt-BR", "c573354849e882016f85b4438b2a86eb9c40129e424a4f15a0b38c3a5d7fa5e4b4d08aed9f5aee8c3b3f7474b46f639dd298a09fba5aface8560ad9685773a74" },
                { "pt-PT", "b1dd82644133188a0258c97c6cea01881e50c676d2acecab5260b2431ac11d15d242234ba98cd2b41c1796acc7b652b19d1d7cb7e7776038d26f73ec0fa8dddb" },
                { "rm", "d4429756e5f856b6ce9dbd0a8116685fa1922b54039be0dca0ede441d9592c729ec01e073c12b0a4a865b4a44dedb6da5a4ae974a3d93cdb814b14b3fcce001d" },
                { "ro", "79270d3031ee5504626191189e2cf2296794d32bad57eac4deec4ee7048554f9589c127e2640d992b01245ca9ad50c37ff6cbea8562b9631b7cbfa7665b50319" },
                { "ru", "e1fb662bb365cba92f42f2716ca0d0c09b363f172a69be43f7b273819e6d4d2594dded01665c46948b9a97271d61d9563f6e52fd6a8cc51e4dc388f29a924efa" },
                { "sk", "9b5094630d18aec5b9b53cd718aee8523d51102a767c3a8690ce3d7815a995529a18034d2480a6feba050c9e720d28a0cffe349bafec69068323cdb8564bd958" },
                { "sl", "f831dfa98c3ec78acdf8a7e72f40121f50a600e9a444a7f6568b29bcc2f4a74eeda3d04e2790bab3c5af2bb101648a0b07d3777993700ef04078617084e5b7ed" },
                { "sq", "67255e418d5a8f1d96a227857e3ecb324ac30a3a14f92eb1c62bcf1444765a878de5b5d0e26723ad5bbc7535a06f7518ba84c35fa47ff14e0a4234a68b953886" },
                { "sr", "97ec3fa51ccb77a510bf4a1c94d868f865db7adc7d683167f8469cb2c0810a224003aedbb4183765718fdc15b0654f063616ea926570b198a8a79f010a715978" },
                { "sv-SE", "dc7c4d5fa6504292412408f6de6a1c4cc6eece98ef22aa280449514def8ca0366ba224de48e89b8a5085bef53b3366e5c9341b9a91d4a895dc4ba463e803f657" },
                { "th", "658118438eca533c504f18afe6f7f3bf6fe01e3e31adffc8a44d261bff48bd101b9f2ac1866636e13ccfe568b52c3eddd8f0d18613107d316f6e6967ea1ce275" },
                { "tr", "86ce88951da15eb92571f9bdbe88f5eae0dce819964dadc8ff2e62f4f89c7f1c578eb85244e627c2cd3b21da422d06ba3535f59edcb15eaaff69babf2d4cd2dd" },
                { "uk", "9c009eaee239aa5dcd128146dd650fd7878d9304b6c30604d47a309732119c4bd288e348d54e849e7d980c85ddfbd9b195641a3c6d50a3680cef98bebce6ea3c" },
                { "uz", "5e3a82dbd5f0e489176417029c5f678da96f6df6eac91d57455cc32a89f8ba2e29ba42860a970eacc9ca7456ca964c5466da1fac5783ef18e0bf54637b9aea41" },
                { "vi", "30e4ed566891805c90df4c5a30067a93edc97e1491233f0602bc6a43cc07549e6a273814e403d397f53506612072ec5fe6a40f59160be014d6ce9b11fd238f08" },
                { "zh-CN", "a1a3be4a7b39dee72a983dc61b47f5bfa2bc5accac1bbff6e79153a205f827d82bd0bd03ef0d6553a5750d22bf04ac82d711f6c7f1b70d731455a3ca2e359b08" },
                { "zh-TW", "cd7aa94d5d59af19aba1a7faadf5ee871e42bc68e36d9897515735024ec9f97884b97d921e4c8c399473f6fbec7b82c1e3dc3ce540afa078f93895cec13292ac" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "903a478abc585078b50dc6cf582b70bef0205348fd136d336c61482c0c4ed20c31c622154a1ec57666d88cf4b673d3d8b647f8842eab2106e76de8e2074bfe21" },
                { "ar", "8d951fb0043c8232079b1f7cd3875e3a0392de9562e4967f83be05bf50240d0736cfe7523f7a98f2ac3e6e473ce58e49ae1fc8df7a2db9307f2fc61b0a0476b4" },
                { "ast", "14c49d13c6ac7aa271232fd345446c2423a9f3470d496f0dbc2207d2dd2b6fdc1624af3d8e3288d29966d8153f119ee6000a0a5a95664804b1303fe547f5b546" },
                { "be", "7370d5562c17172bace621c31a808ed657ced5cce4415743c073e477ca382c1c78a91e9dcfa91b9a41e11faa8af352c12188b5860aa06b13e565ab8e4a12f69f" },
                { "bg", "ff390f85eb4a8eaee35768161c48df50bc1f379d0d21b15812659597e766b6ae12c63e48c8788e59917e6338594e981e48df304bda49cca8e9dae6b8983a9f42" },
                { "br", "10e98f186c84b5c02896b4f4229988c337c71eaa32ffc8cfbab021f7c5dbbd0286af4f526717ada53e878793634d7e6ebc7ddef20db0be5d970193b6b291ddb9" },
                { "ca", "6d440ca223b0af140099f4ee767af794363c7d07af85858de4c089a99a9bb357bde7310a0a45ef0760a61e5d7f1a5208cf9873d4c335ec8e26a3f48f3032d2b7" },
                { "cak", "96fa7e5bb04f2578ed7d3ef0e9c543b6f6ca61d30029e3a8a161ffa5196af741d1f303c8c20febc64fcb3f5392de16c3b7e880ebb58103b5c3250268cf69c18e" },
                { "cs", "f7d62d273c2b9ea40d0e543826ac47815d17b511b8f49d302ed60602b542edc84c2bf616ee5d22cf1d8f5063dc12efb20e933c20988ec9f01f568d7c693ceded" },
                { "cy", "c82d6b4338d88b0c03d7a802b5c438ed77eba4597ab4cf6da6d5df6f815357774c0ef0cf751830e9f38b2f7ec297b831e390b5cc4548f2b24b9a52661974b976" },
                { "da", "5885e9e54183a220085a908a2076dd861b967e0b7e5a834a6ac48b26892dd97b871af896cfec09dcb429ca695fbc8de88b277994b75890f3fb00ad240d0e6fbb" },
                { "de", "278e9b2629e03c4e1dc1501f74e1b57f3fb60339acf9c23d273a774977e4f23bfd935d13209eee7e629f89287b7ac1ad7c2d4117ac439d0f9e3f29bb2d226957" },
                { "dsb", "027f3e2d0dd639f37275b16b8f9e309ae0444bf3582c9d8969a5160b9b31910f81e0b21ac6db8ba6e12202bac188a0810052ee87f320d3da625ede70f5594a97" },
                { "el", "061f4d0ffbd1827449c8f5f3f5affd70acbf6046819aa35b2b0dce1aa2373d67439e60cd8d913805da8540ca521b439ec19aa9494d560de79da2f984f5abbb43" },
                { "en-CA", "1a728ecf9320f261638a1a0ccc1a7c7c8cce8f6d06652372be4b2ffce092ea808eae96b54f663663eee10c04424cb217ad2b9cc2c989b957e3b8c365097e6e2c" },
                { "en-GB", "64b2fbcbee7e156af903ae162be25dba74cd8a9537d6e004c52f3d9e44d3dc11b179d2707d86f20e18c1e8d1e8e96e1c74bdb1cf3b590354c9fbd07521d0b99d" },
                { "en-US", "635d662988d279841a7f0407643410afffa5a2670081ac16107c51b14d85f9631790ffb01119fc1d51a5762e173009d636d7bbe0a32eba83496e669298d49b32" },
                { "es-AR", "e1f0e73f095df8e6712da0b77b2863be4dafd3c5103d933e3e6702097219e29025f4b7e1a4b18750e0a990f6933020612476879e538e3e75d0267a78a5f73626" },
                { "es-ES", "5aa00e847c4050da2c490e620b096fc6cf55fe4872e2f7182143b684d0f7ff439ff2d9016566a09e68e3fad881ae085eebd741418f84b90e65b289dea9d75a36" },
                { "es-MX", "cf3ce3dd48c71ab90e2a47c998627bc93f2154b21de04ef66f70711e41034128890330d200ddfef03d037aaf284b16af718c7a865272331c26dcca296513ff39" },
                { "et", "0fe1a3dd13772db913332bffb4c51b6ca05a03a4ed2cbdc1a25dcf50543a890d9be4e743aca369f70d28aa2e9188f9970e084c11a08949dbfb081399791eb199" },
                { "eu", "6786e0bf3070e13091608e260bca42176e49e9c8d7bf38970d6dd049696dc95310e61d02beec4dd1f4b632fecc91bffb00501b9777ff2574326d4fd9fc882fb6" },
                { "fi", "0c307099bc5e46122ff2892c5f19df781a4701109461afbc512693aa22c30d8279775dcf0b54f2d7817a66aaac076de96f3f0804d62d7a6f16518e3c28301db0" },
                { "fr", "ab3fe366501943c7a2e8a7835d241f2e74eabc6b80e5c71a46a91dc33a7d5386892afc386245337a7e6457d1e6f8c78ab141478fd9eac7353522b9582218f8c0" },
                { "fy-NL", "f4bc27527bf928a3db9a0e654acc93c8a765ce9e400608532a6ed4186e50c7ff25080b9d20dc47462c80081e9ed80ff5f18b052dbdec90994317cde1c98252f9" },
                { "ga-IE", "d5d9e7bd259c1affe8aaea1a68cfc879352c30fad9098121dc868966e81dd34f056b0f5553db02d1b6520048b8e160c2b8f3fe10337446bf5e58f0bf36ab047c" },
                { "gd", "9c56def5244b776b28b45ba257c59cb95ebf4b685d139bd19f68f206902342ad6553d645d55a060b3f657f222d547ce8f0fd355d7fdc9ae338d37b78b0fa99eb" },
                { "gl", "e39e182868518b7c834689a6d282609e486f50343e473f726230c5957a5d231566cd54738810959028aa7f593175f29e0610f0c112265c01c5d358f366099576" },
                { "he", "3218c3614fce1f3dfa9cb1a7e011bfd449d8d2b98317541285d14a933dd5a277734a7ab0f03b59f9681b4d3e1b712dcadc063bbe2a84a595b9720c129eb44a4e" },
                { "hr", "51e521e10244095920655e1c98622bf5922809b1b391f4478a25337df48457be6ffa0ac109cec30c24111b7fc76656eb72a7f6af7eec978f4b72addffb6b3ff0" },
                { "hsb", "f6179cdf57de23123e7803eabe751fe2322f9e93020ced453de1589bad2ee96491ec3c5507477a560deab328ac6dc8a3d8dac80cea40ebf285b277f7836b53a2" },
                { "hu", "420ae6a91a1443c02890fc00575f38a52ca2eca9099f2f4a03fdb29d860612f1558dfd883c81b9dd74c0e5d001b4d59a8135f74b752b6a2c353c7270e4cb96ef" },
                { "hy-AM", "ef9f9c9c9c2f60bdbd1644173a1a7af16c4eb11d8db922040bcc1fa17c2bee4d376cfd3b6a622c2984117e08bbb99700e84521b889441d498250c8749135d585" },
                { "id", "e1beaa7d1ce421a041c4daa648bac5c1a544293b78339abba5c30aac0b52f18a569df8e3b068f81d2b68815a57ed43971131e0a3570d9b046b41d3bc11280ac6" },
                { "is", "0e1596e414cb2dcecd62ac99b3da83894f923f879367900f156f273ec4ee5ebbb2ca4ec0387eb11d6c65d8bd3929be6eca9f30ea755dc3b84abc6b45b4a5f775" },
                { "it", "b452ee76b39238131953056b6619d074325e460f24329e8a1da1a88c2d51f9cefd7b89a5d181624b8272e64fbbca852506edfb9f7ebfbe58265f2a9cf2816e93" },
                { "ja", "d87ba898ed59416282729b77e30ba659ea1ad90d186a26286e0425ee5355293c95922e5e352425f75667a89fa5047fce38e64016d976f19353f7ec3bb27c2f92" },
                { "ka", "1cb698598177e100663aa520f328a103237a46686a57137b228556c9ef4eb6074091e91d964b832a57e8b6fdbf2215d47d80aa385f0be2fdc53a42a09dec3a08" },
                { "kab", "0bfc4c91254e546863deaa0f85d058f7e5954c6e7a79c6fda3d2bd02068a4aae02e5701cbd989e14da0cb0a7e2d5622995a3d4ea1d907fe67ffb4b34c1a274a1" },
                { "kk", "0e48b9326c36db2647edbc1fab9b9a1d5273acf86737ffab7fac3f475cab582f19ea4e9931ff27b34912895f1a9e14e8f63a13d3ac7c6c204da1ebdff085afec" },
                { "ko", "7a938e1ac76f457fc06992b6bce96f11725a12af2d2eec2f60b9af6c7b13919a353cfab4799ec262c5714f39bf922305f5e8299a5bb36fad1594cd948c5d7a6b" },
                { "lt", "d7a413158b6934467098ca3c8b56af6fb4dbd87485e93217b9cbcfbad99ea5a820ad474f0d9bf7dc8b666418a14b7e2566602e28ace0ecb0857345b822396723" },
                { "lv", "ecc9cf2f7ee8b711dc55d4ef4db8f90a825d5d218781b9a1d500f910b6946b0c1b59899b9a5fe1573822fa094d10b620265b4154621d9a3ceb803b6f2258144e" },
                { "ms", "fb7cdd7575db8225bb161079c1e95ab74475e9aa300fd111d2586f44ce4a55318ff69d4925f2baccbf482f9bf80fe01fcf6600596a1f4bed3c3d5d571983989f" },
                { "nb-NO", "3b3c0a897bc287fccd547b81ed6f491750c367c2cec09959e9c365e9701cc88b5288e758a1b70838e6a8d9cb17cf981af2a3a3952ec9ab8ad62154721aeea2a2" },
                { "nl", "194327da653dd117c617a77797d5ac51e35f0a06f1dfd0c0cdee7837ad045bf4ff68ebf35d6a3f735a446c14e5a9e8c56f67fdbbdfb152547d07a2240b2b51fd" },
                { "nn-NO", "5f8aeaab2e6aabda3d9e2fc817f0a6dabd0464fb74c976d8af9cf7a59701b2a3ebad0cde656f154096a82e8bf282fa96bef24acbac832a8cbfb28891ebc09b87" },
                { "pa-IN", "9b949514fd5c6eb361783d2445b88d9f9bf1eb52352dd50ed925f1259298f9a80cdb0f0029247954a4d57ae8d160c6ce4fb1366b860b9c8447d1e3762faf25ec" },
                { "pl", "a2f66dc2a209dc82c84b47229cd0d7f34b3f3edab68264c516656bc4c7ec687c5bbdcf5ef8d825bc3206cd8d0301563fd5efc989bd71ebcd97225465f53da1e6" },
                { "pt-BR", "caeab4b333df0e23a49f550934acecf1c9c3072cd164319b4ec215a9a53089f3bef940bfd50939bf882006ae0cdd5a68f1e75200faf06d4cd768214e54d1d210" },
                { "pt-PT", "c5d590e75b6b3fd1e895fdb9d7510c90a443bb2f1113e00b85a8f7124a05234f97239428e0194aa0da2897d87ebbb8bf08d429c6160cf02d95566e5a3183c7b1" },
                { "rm", "2490761998d0f250170683c66e1d5c59c9ef0f6a3dd695f820770cafe7510d81503864ed2c5d2ba9ec8ff8de98705b3dccce32b6e7ae38173ee0626f42616208" },
                { "ro", "a0ad17baf45cb148cc731f9daa7526c73dc36b60dd3a922dc86f1b3aeba4e8c65b1532bdd5feb197cd16004c194a73759f3228d86147ae2845cf4a8ab3cf8ada" },
                { "ru", "13fa1ef482f6fd57a4389439ef83c6cd01969a271cf48108bab64eb52e9529c7ee87335424f6b958a082bfc6a9bc0888d14fd0d85e7af4f9215672a8a1fe9ac4" },
                { "sk", "4a5354d8d27c5e362644ff9103d39a80728a8ffa330bfe7d07b834bbc2a2aeeb423cd303372ce2afe46115c71925520bdffbfe7bced2f8a936ca00ad26f490e3" },
                { "sl", "65dd638c97a9c7b632acd6b37256bda9c181b2b8e0d70058e64d40414d800fc69a013224ceab4b304dedbd9d463a24aa508f258e53bef92cbbf280534c2624b5" },
                { "sq", "3960fe60e63d56e7bc4dbb8b40d959f3215f579405372f8bf24ba9ab5aa6d39b5bdb9946a62b4330fa0f71193d44d0bd920b4a60c58cd647601f292de527f718" },
                { "sr", "1fe283bd174bb2ff06dc91671c10a58251cd21f33a280f19fec2e425471697367677d2e5288bad3c3428c16a7d7edd6d6f231f785ac3d947c152c36440a5d453" },
                { "sv-SE", "9c5cc85a5311cf8e8978784056b557e04273e6b79f549f754f1d06b6690b44ab949c0a1e1dc13aa6cc9f1c3640a03bfc3072b699eed3d7bedf60298bb38b6bc0" },
                { "th", "4b8d08bd4bfe731e3bd587899c07ad426c292c0c9d5bc71acbe8bf071f05ecb2c9801b6ff18ea554c2ad210d8dfda84f7217f7fa21b956f74af34f9e0aa4bbbe" },
                { "tr", "222e4add02af3352154b52420a47cf09d2fd7c93923537c38d8bb14f04577e2d84ed1e22045efe7b4a7960621d733fdd0913155f3b9ef94ff9393e2dbe0ad2d8" },
                { "uk", "20ff4fdb1de846a5716e4606dbe4a467cbfef543cbee62ce1aa1d7bfbe18913680466a84bc214f6cf974404e65f122448be28ddeec7cab7de12b3ba997fd375a" },
                { "uz", "958e0758ad569cb47a9a93a944432a781fdef515917b3673216fc3f68177d69080220e909c51e8593c0d0a7ab300147a8d90bdd916cde864a8fcb45d99887a7b" },
                { "vi", "03e5c7db0ac5e37fdcf672e19d7b219c2e12d6af13b60792e5801c523e233843870469d49e6263d6796a93f391c17cba123a3f5458b340e0770908b61e3008a2" },
                { "zh-CN", "0e6dc3e99fd4aab5430954578aebd66c400a9c068ae6c0562135ceecad0d15a22655f9bf61a6d054cdb5f5c6f7a8ee4fdb68e6278d8c94eed0f6f48689ff574b" },
                { "zh-TW", "40804fffa9e164f742f8c846c298393cfdeb77fec8173a7131e84bd2e0c42a72e00cd3019c375d0b040383fad90a8c4b7ce797df65ff7f9f1adbde2c8cc46058" }
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
            const string version = "102.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
