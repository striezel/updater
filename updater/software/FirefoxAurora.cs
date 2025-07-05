﻿/*
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
        private const string currentVersion = "141.0b6";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d055266b41ea5f8b2246791833af01c6f471353d5d562fee6b964b3b0293cba248e2f6cec800560d8d0704206ab9e485c11ad71651aa62d933cd9270e29ba91a" },
                { "af", "043c8451473d358e7571047fc4c7eb1a3f482958771cfcee2a3b53f60e8e2481a61c810140bc39dbda574603c14eabdca773a77b04716ef911bae2a196f5b90f" },
                { "an", "4c222183edd477bf1a854a3565bcaa5175385025c79949377afcb5477edd7d42128ab4731bf5f5e87b7b51703b7e284c4bf54ebe2191f03ff262a518bc0654f5" },
                { "ar", "396aca250f671473e8a2ed8392573003ce3375b58844a5c0217eb26a5e91b735f6ca15da0d2a5e95b78b7f957827c6fb0a48c05f2063ae4f3c7665e2b61a2e90" },
                { "ast", "b9054b9cf9bcca17fef6131d551573e0fa7e82ac0e44b614dd1e6eb5a3a6e2c87a6efb9f77f40284e8c0656e934ae976ccb32b0a84923c0bb72bf3e02105327b" },
                { "az", "33d78d8d7e93d02361a2d70bb0aa22f94416311877553c3550c56e0e356fb8d0b586510ca855a607cd4a1f033d9a0f819c171e5f275e5189f12bb7875ed87ca6" },
                { "be", "09e8dbdabe9c63c67e40c595e8b584bf2a7d1639f2d2e7e877f41a4cc9b5d574956d13be1b41124286e8354c1211a449865d88f5ebcc23109202676441da8991" },
                { "bg", "54173740ed7584aea74dee8d06da5b17df79337a3ab1474aa7b11c2b0f5eaac42085c75381e946947bd46bae24b49769de25cad9534757f023a31e86814a6d27" },
                { "bn", "2f66d58e89768c5bb259402451d4dc57cf3f71702ee778adba0013232c22595a3a2a1689f459c06399e959f7cc66ff1f6ac2cfcc557017b5fbb01646948e7b1a" },
                { "br", "e637c7d9fc27c4b48ad7aec0413e654c2b07880e348977fbc1f1ff8ef2e0461d65ee71d3361f74640ac26b5af65349e19981a17c06ec0ce4399d0c81a63ac3f7" },
                { "bs", "262b5efdea7634f40cddccddbc207ed59fa172d316c6008dbc124f07264fbe5b05fff4e59390283c7976c0568226e1d5ebaf12538d564e1c8cead45cee071b77" },
                { "ca", "618ce648ad064cdcc65c35ed50f9ddd9d9e2798a80e760be4f7d02010ae4f4ed7fbec7a76490314cb548bd30efb0700df4d8f08b8f1325b8d8a2605fde2201e9" },
                { "cak", "b404e4cf39ab545b95e52fbfb82352ba9a75bc1142f2790c3780db4e1df91cd56f4af1f4487df38c3bfec41c5776f44ac799cbb5b487446bcf0ea6151328a403" },
                { "cs", "56230d09c7d4d27e8b035c989236bba9f46f4bb3178720945fa06bf93dd03a1ea91714c71b4b9398e7fca538d2ef9cae927a37978c553c34c599d056f152dcff" },
                { "cy", "c9b8157f98fc1a204cd345fe1d660fd0a1bf77f37dbdd7eedb6a19d19ecad82e38807dfdd38c9dba4012d123766b8a0a546c156783fdd479bcdb1312fe860205" },
                { "da", "90f63818855bc7a83132e11c09a4745f7a54aea143cd82896e1cb3b1e1a66b2ce10c0f4b4070b7a69386ae160b992c21636cac1f015754320bee2e2d8d2560bd" },
                { "de", "5ab8a2fa1266e5a334b7c73caef872e088935a012a08c78b8a55c2c32ee94b65fd20f7c269f558fd7c51b7d89fbd818f6012c17d3f6dc87241cd590ac26b2b72" },
                { "dsb", "d0152f088370a7e356a4c157a0ef4feb6c828178d71b5ff27c0d7ca534bc26f0f0bd60df44a29661cd2ca6d3d7fe2c2352cc3fcb0f397d0f762778df8c6d3b9d" },
                { "el", "a9f3cbec3562d72d948e8cafeb5e226f9bea726386576db7ee91bb6acbccb78e44b62fa6a24e3332011be6c73513f6b79aa6e20a0de2b38ec4da7bd1fb9a3055" },
                { "en-CA", "8f9effe25355657a193b7bab96bc2ba97cc9f6f2d167156f143e90b0c2d18b8e133a839bec5e64adfe62069b482ae6b6e0d0b106395982bba876639b19632c16" },
                { "en-GB", "b7033e45208e67ab87963d83426ce986fc0dbd55c00ec345d2c5746a35fd5c0d52749dd75a5eb15361975f72852137d8703cf9f7e8541c4e24f182de725aba81" },
                { "en-US", "dce266328b81d517ab16e4fc5912736d47e36a84034723bdeda911899c38e3d34d3694533f3eb5490220ed094644a76c0b22cc54f0441d50b51e7fed4b2614b0" },
                { "eo", "bb9f4fd1300a5103028c47867e8c6b278e57c7009c8bdf46d6799c5a02f89b8c9c563e6033c3aa462b718bf6c2d38a9837c20affe9ddfce4809194bd0a8a2ab3" },
                { "es-AR", "73ad07c66fb862fe373a5d5cf9c159cd52e1c54d46e4b19fd9f5c53a658918fe44fd10d561e5d91fe8f18aef7ce9ea1e5cd8d94b52959a5885babcde556c1e64" },
                { "es-CL", "35467fcb05121fa2960d29d9e284b12f427450ba33b2a306c65b321bac8990c722166cb753d69d1db8b23f9b8bef76f554e88deefe8945be36e2244ca2871d7f" },
                { "es-ES", "fede157ac61f81dc6a3a32e5370bbc2d843c5ff870546565e8e656fb7496d26c9b6195ac4f519db110071e5031d1d752c38d7af7d30bb8ea2d21c4022911626e" },
                { "es-MX", "22ab6ba39a0bbef222f4e1b70fce98369317614b1e6f740011945da1307d5f562dc6306a13de0d59af4db9e85e8f4ccaa2aeb9f0c8566dc15156bda086799744" },
                { "et", "7eba41a15fc4128a5dfadb961023e05ead05cd1d61bd0ae3067e6e5b0e6a357ff6cac3d845ac47ca8622a844f284855828a9bc14502e2cfcaaf1c583f082d3d2" },
                { "eu", "089687fb794ba29d4d26fe14289ad08d9e76f7ee8656f1e44210e5c9f858efa0e99396713ac8f90f63b944659235c47bb6fa3371a0a7276e1bef020a002b68ee" },
                { "fa", "bc878adad27e654b10eb61a75958f8f601727c733aef116427be620b89ee37f035da1b448ca641cd0b0ec841f9221a7cc6b222ec70a79ece9bd41fd865336cfe" },
                { "ff", "9803d83c64fa048b40470a31da3b3323ae160ba4fed738d0e916127000ab6573e72f25233ea0b2b107ebbf0348c2a9ae5ef32c542230eb8f14a056ae66a05892" },
                { "fi", "879f79982507bf914b2bf5262476d1c3d3b2e90339dbc9ab69b183c9a870dbaf5f39463bb87e6e7def824cf26ffdd45f4c2b9355a1cb6ba0a7846f577d582a7c" },
                { "fr", "2c80f9b32f8739c035b0ce04a43461dcd56a91642be7214dae877d269e6f645659d49db95b1daa09531241da4f1763ad0f5bfa599e9c8577daa05dba3556a7eb" },
                { "fur", "0bc9c94872e525a256164700290a8b363d1c907c5a56c2d5923b377625d4f533eb1bad7cd1bea102e4924050b1c1ac4e6ed71c9f48578618585d6431da9ba6f4" },
                { "fy-NL", "c8abe9e8c07b027baea08eaa25d3a3e6614e16e6fd6b24055cf3255a6b490a280c31e1a3dfe13dbd9437584925600f2ab99eca257d3e4f7d26f7b352f6e35943" },
                { "ga-IE", "c168975bc25ad350542837cfcf4ff70ff881b364ec5f398dd3788a54fef72d4f56e0cde4018ab686fc4af91dbceebe9adb0c8af0e274b36c2706f3039a703be2" },
                { "gd", "1c045016ea9bbc8fdc44fa35bb01fe076506c37fe0d1c2e6ce7a6bdfdb2e27b264e337527e77a2ce6b377f5a389e9cfe1f896b0687467c214454ab50a28545b5" },
                { "gl", "1892eace865edbd29e253ffed606beb83971e3887db5f831c9e4dfa332c21fd5ac03182e2576bfd73f3be31395db33231bf70a0b21c2b1cc4e26417165055de2" },
                { "gn", "799222b5c18f903679ce30f1df9253bf9a3e4f9979df8bddb8312d9c82b59c1c5f1770b09739309e372e6895d7248f8dff1846ca5c4b972b3ecc588a6a1aee36" },
                { "gu-IN", "c3d29c3d170832a6acb003d742e81bd6d603b88e380d6b0ee1f333c79a980b67a6fb9addb6377e1635ba336fa287c7cba401b1028614e7fa9b83f873b60bc4c4" },
                { "he", "b98abfc6ec1f350d226d704fad5e51feeae6f5c8469571de17db75f551dff42ddb722aeff26558ffe817b8bebf5614d1beab8f989adf511bf8929d780da01cf4" },
                { "hi-IN", "d864e3b64d0789131d3c487f00deeed69ec1f68b64068a54400b1b10fd9515b76f91c2a26f4d2c89a1bde8ee770bb4b40548dcc768d05ef49e9d2a417022ffcf" },
                { "hr", "b970d8c90f471f28aebc3b6188b8aec91c08f1334ad1753b049584f5bdaf55a293333e0740b04d6daa41ba061dbd171f296d9362af1443ac818efd27c821a4f7" },
                { "hsb", "328846081609ac92cf0c180042b1550b7834c99c4f79c5a6bda49ca88bc24c2900ed1cd9843919057e22fc1df2f4978fa07807b81c1f6e7a9974ec335e74e3e7" },
                { "hu", "c2ebd675857ec34b3a34a7f243a1e65774b7d2e36e541b7f9fba4e1002170cc176af0623d72eea0f9be1a9f8d44b62ee46e65b4aa0cb3df4d2e81335663f8058" },
                { "hy-AM", "c1ac7208f08f29b56fc8a138a05183bb765af7490abe0376970b46ea399896b7d172d7da38f2e268540fa291fa2f5a17899d64e13004355db84081e46354e723" },
                { "ia", "964fc63f6d1ce3d1d941dd9dd3fe9a6d65e6347b1acc9190cea8e04e94fea1c6f44a4586b0a4f48c20aea8382eaa4979b1b3b25ad5aca4bb5beb9a93592d9268" },
                { "id", "ab912c3d129cd3bdf8528c243813c3408598819e2554852559ebdd0f61990ffa338ad0068b221edc42c5798062657f43a6700e6b7bfd376cc882ab2a532fe005" },
                { "is", "6241027f38c5455372a10176378d657823964ceb398104c534e30d943092bae9df12451a1d70c90a20d889645bc6f8b143791cb3ce7ec0baca3934363f68636f" },
                { "it", "afc3f429bc039d0cd146afb83c49fe01235024bedd447ed17277d8925f0bb10e41147204677e0216443cd099dd56b8248e6c039ed10295845b9b8d91c578964b" },
                { "ja", "3c572242f712d0c04dc9732daede7aee76c43775d3c9957277293feef37e8345967f68562651fd60af9d37859772f954875c1f074e24ae0a469efa02129ab124" },
                { "ka", "06a08e9cb975d5be1a7ea258b35fbdc004b908f374699255fd41e42c2517969899e995ad8abae711dd9e54249a83b468807bf0c1301c15c1b9c6dab0fc028f77" },
                { "kab", "9f576ed861ff5bf09f83212a48f38452a5096c09579b872d3ff7c6c0c1fe7a23807eba1bd6106f64982906b6d8700c35c10cdf8b339f34392f0d1601bb85dbd6" },
                { "kk", "66d14b5c6dab43ac137d9e2571a77c9dc550c5bc616c8e93caa55e41e08552d06abee04c8a5d0769d4b4986ae4e0097b2ac2300656a83778f38cd9f317c2f939" },
                { "km", "b7e25b9e2bae0ecfbd108b3c1ed4d9e804da312d3b52ae4b634c0df946578413042527ecd93b2f977663a9b21ecac9011af2e2b62915b78cc866969ba1fd2fec" },
                { "kn", "2e5e621c9283e43e99be9147283258805f1e805bf56eae38a2d54c8248c184116dda201ef1be82e7fd1bc270ac9bc06dfcd1c52076d1152c41fa93fcc0f82157" },
                { "ko", "a859df106ea0680aa587a666ca8cf0d45a0677c9ab756c75cdb289e73b32326f59d00be7e57520863f4c4cb14854a4809e96bac84d93d96823be8fbe564582eb" },
                { "lij", "f5cf1f34e8e12e7111b3680d5347468e8053603d380e4b9645997a5b7d0eaa946539b75d254e3d0fe6a1382dedda9c9f1afd1f94628c802403efe943a5726f85" },
                { "lt", "3cc097e500f8c635f4733574e6dec20003a9b7a21711350a96dc3209d52128672ac17230f795556f753f8ce8360c1d83a19b3932456e0a290e45117c07904188" },
                { "lv", "eed8f8b804101aded5c2eafb4e4761f5b443f663fbc49620037d3337e2085e6d9e9a46858024a34eb49bde598659ddf88ba96b09179dc64cd6d8ac76a367c645" },
                { "mk", "402a7af4db514dc08e55c763b0e98867cefaba353594c40f25300acd58e5c6737e483c978305cebe1b3b26066ac438de191d7f4efbb7195df3298c7a92ec6e36" },
                { "mr", "112363cb554f4b3d030561466b94f95313817eebc57a0076433c37f4afefd6eed57189ec5e9f7fe6d1de55d7631c6f193bab53c22b5448de1e52407afe05b060" },
                { "ms", "f12d64389931151c80b0c408f179c3109c8552b82d8f5aa2b2cc90adeb6c7d30fd3f9dd136f09343ba53772ed5d1866450b891c56d3423a640cf36113cde4b38" },
                { "my", "b46cdf66209b180a58df19e6f1a1633533226ca41f59d50f4bc0564a58e7db538d3f84c168096fa53eb7255ffafa9f7d75f98f0789cb9d51921ca4de09007d78" },
                { "nb-NO", "5cd689218ace392a5b77f94f8ae4ebbc70bf0d19eb974c4c4efc1650521d0a48d705bc32c486d5bc47030ea9f0fd1b39027fa14295c101aabe1a879d230ed016" },
                { "ne-NP", "5b8f5a0147c1ed81be2913761554922315435107c286b63f9278addc9cac24ace28ffa35e67d7b346afd48003e163766b336587c1120dd00dfed336b63b33bfd" },
                { "nl", "2cffbc8fa8e962ad66d2a7f12ba29b3bda50b346c8079b9929dd0ec34adbd0b56d95c199db90cc32c7a7d10eee320a85459d423d91f964fb3ccaf8ab3d12c861" },
                { "nn-NO", "aece12380617b0f825e6fe74775cb8ddfa37197226c7d6a5400c3bbda813b5ae94e4cce2b6c641164a0b6d2c42ea5534ddcbf86df85a3dc477c80bca233dbccc" },
                { "oc", "40fd95c063a3529e0125a9e2bf8b2c8a23c6532b6dda082e6fc9745cdeb252efc6facdd5ee5448ad60748973053f5e0bdc70a65d8466ef48436c5e94bc16d44d" },
                { "pa-IN", "02e0266c831f240c6e2dd0e366735c9baca699fe26e59c909ec90f3ee59922660aae876f37654c4e6ab4d44d37af9941214cc5c05fe08a7a93533e5ba4212b41" },
                { "pl", "59caef76177ae44590ae04e741f4edbb5ab07831eb77efbd8fe162d010d4db42d70e1c5dbb9a82a25478c81edc22fa3bed006ca04002b3e3a5fc476881214e54" },
                { "pt-BR", "d35480c8d14f204514e2b4379a9b6c08f0649cb9c8463d514777eeaa9c11dc562b90aef85f02e930ccf91acf8401f7f52a687807a9fc31ac242d4f7c28cd1164" },
                { "pt-PT", "8fa63f6153b278a76394bbf4829a4801c6bbf9c3f9ae4dab9ecd4ab167ac6760a640acbbd3931bb7e1c7c1ffc897eb1dd6f0bce57affd1cd96eee375f967d927" },
                { "rm", "8ee4a34a2bb26a43448e6cda38529db82f75d6afb96fec247a956152363219ade09d664416c9390a7edd909f5765fa3a0191ce67a4b6f123ecfab69cd1350cca" },
                { "ro", "a1a45a82526c61e3d5e13517d92b73ea58fc757433d1d214c34ec4165e972997f7d9fecfe49d512fde9a2b14d77a05e65b4d7227fee9095a14888fc768de999f" },
                { "ru", "44ec0c2e570e39c03573f075352e5859c7d2e64e9cd2e66930d72a3706ce6c9ae09fb1360e232714c6e7a4fa76f23bf9c0d37e94b600c360b536346ddc7c75a4" },
                { "sat", "33aa463ef6f49e156a02a230ff73c822b3c0ff5779b7a9bdbc3eed56929d4e44d16b2387ea66a8343d527baf2bc7251043e59afd438dc091f73615bfec767c74" },
                { "sc", "4551fc3154284b14d262fff3e7fcd725a51c00b2d3485d89c68612a60c5bfdf2957d19a11d082e8fbd50ee7a77f284c21e812a04034a63571d4d97c7f6494eac" },
                { "sco", "81f8ade9f8e18677c0dfd3e380460a0acc7708a01138b457189381abe15e171cad35025f5ad443cd164db37cb3fff425dec15459fd5d3c19f4122afdc2ac7a65" },
                { "si", "fa68ea390d8e4e3d77822b038c0cec1dd0a25a5cf1430d9329820e5790bcc98304fdfddf19aac308c2db865f7f2581d765556c9cfbb69f516d770ed736a8e92c" },
                { "sk", "96a81576f79e95c60ebaec404769d60addc8dea3b0bec92974cc7758ddb82693a909c927cd804dbcf67f762b8d8b1fa462b0157a801613781705cd1950f66a1c" },
                { "skr", "032ccbb80e1c807af9194b84aca3109cb789da754baa99bc5e48fa1604164c9cd82ab3ea74c6b305ed7ecc15d1f47d6fa5bd794c9643b168edfc8502e77413a5" },
                { "sl", "fbb55e2c932f0b0631b9a890adc8c9470e16fc317b88bd3a3fec9134521c2384c7c350cfe0770c8a4baeef4c09e107ec6f38d4e49cdd73feb97d4f2f0dc4c6d7" },
                { "son", "d43ad58954cb09844e1741bb0232c92cf9f951070217b966f5d4563d0a19791416fb8bf9772b33722c22e58acd72739ed63d8f4616a88de4cb5a4024844609b4" },
                { "sq", "2d4b82c5c9d032a597f57709cc41abaa6270298d4c56a6650061e9c0dda435bd5cd9b942a3c4df16ac7e5395094bce18a771a5272182dc8321e5b2846a0d86f1" },
                { "sr", "b4027e456a58c7e93fa6305e57a31f28160a5285e0f4427973f7379f974fbfd36b56280f7924124f93ce2025d562a44a3423488ddfbbf68be85993f50707c815" },
                { "sv-SE", "a9ec9be2c945bf6e225bda5805c564b6607821c33e5ea37654df45c0b5f3c100b65e2a1f579e75b93ab50a4f17500d74ecdc0bc065e7dc5d2fddfaa8113fcec5" },
                { "szl", "9a4fcd916555499918dd7930bf43e83bce68698bc9a54d069f6bb21793d38cef34de98cd7278abc88242c52253294a7c4b44aeb7c7e9c7f9e5412ca9ed9a9af7" },
                { "ta", "e6d7c0d1313b500fda065b16ae61e55f46ee8fb9d1611bbf559f84c5a6b275425df41c9179eef19123e41378fc29e342e9716c9ad6f917a13aed1d6ad79741dd" },
                { "te", "ab85b8be1c20a389996e7aa74162ce5b7fc5a7e3bfd1b4f7bd2307a4f3e73fd82adba44fa60daa3b4ab38cc3b1085bfb8ed9c90dabb0610fc4365c8d65d4e3c2" },
                { "tg", "15a68d062388f378d0ac2ce35a92fa9acd85b4ad5533dfe0d5dc4c3e394ac647d949a8f526797b95e1a7014ba74198f37f792698a44ffc2c026dd984a776214b" },
                { "th", "6b95ded5883469b47c9fd076b2ffdb4079de5c12d193c5f66373ecc982ab18e572c83e54c27f69fc992aff61c1a024042f8c511f984e7ddd676f64bf4b20468f" },
                { "tl", "b6f4e6b95142e98ce48b44e6b6fe20d94e34cc882afffe1f0a326708334f416e7ba1d442c3849d3088e5ede47a921a0dcb15411d008d176333003cd67a00d291" },
                { "tr", "2fe21a96b460333d5b156ac943422da2c2ca5889aab1c81156974e3b328d2613b39e22c4907f3b28c7b82197850d9bbc56e77b894604f299263be0f1802f6fef" },
                { "trs", "587fe63b7ba1c611e6bedf472a17a109b090784e13f1617c66ca84c995876009907034fa72db1cc29b5c3a55a051cc00e8a07b10506370ead3fac26e8fb5808e" },
                { "uk", "6e00fbf79fba87a6cebbe270da9daf87fc149fd930b4bb44c94065cfbe7cf95b526f6ab59498a85d6a620f708da669b32ec6322909bdf4b64750004edaae2692" },
                { "ur", "f1e99a49bbf6f0c28370601adfc9cb930c226f1317c97f1bf6574583ce5add244756e6ff00e6193af9cf420ddc57a79ff445ca1719bf83c47576ed0f85600f32" },
                { "uz", "ff08d1da807ae0f5f3f545eb4e87f36cfa7217b0c786cf2cc950a62ab9cde4b75bfe17dbad91e60c8f222d7f93e3b291c0e7a4a343b9a37a412123f6d91a8fa6" },
                { "vi", "50679ec0770fffe2314f61643b413c7191e5cd62eda8447f30a4caf36c7a6f9e0b407c39ec7d8b0d39d08ef923dd7274f98d8b5b68815a93df9f7b133f680749" },
                { "xh", "6192e9853a9d135ebe7656ff2ea00f0f2f37300b46238a32bc17ea6e361358901d9ce056a7e79e2dc5305ab9443e70ebf1baeca29ce1e119b0d652b848d127cc" },
                { "zh-CN", "58a6404084cb0cec3d8f054526aeaa1ffb0f08b78ab5e9f0e59e5eff3c78d2dea41aaf76fdc3c8e9d4b09f4f2b97747163bc4e7752ec34c31bcbf4c98835f04d" },
                { "zh-TW", "f70c8c7bd66f77a2e359bb7828e0ec1a940accf85b1e3fbda32f6821a0bd332d5ddd9c46e4ca145c4b3971568f3815417bdcbdfbf9de8cd45b89e50272ce026b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e3fe04dde42dc7e25b3e2532d029821870d0d7e1906c6609e991d13f44ca7d847a9908307839cece56f15f4f94336581af8b63044fc081146eaeab551623364c" },
                { "af", "7a1cab4bdca674c8617dd7042c0b5c9b8c3679b663f63e9442aef2f07976c2dd07e90efe2bb3f9b1b73ff3931a1e6b9fa31eb5a16ef4ec366b46a831c087d8cb" },
                { "an", "df772df1d7d3d5b6dc1482cb6816828583988ea70c1aedcce24a7410e96a4c6ab4916987be280652579e9576cd9e2823e4d24cfb95e349e0a3da3e2a24bcb306" },
                { "ar", "2f39a283935a8bca638ac80e21a198e0508d802f36399254da0aafa8d1f75736de13d3dd9cfd5e79494291aa44d57dff89bce686c8491dc573f8391e2e130c89" },
                { "ast", "da543a91dc6558b163a92794f08dd22cfbc74785f5e0fc9adba3922459ee2df8e69dbc078b0e882963b2cc23c3278be39299fb4f1e458930ec76edfee679a8f9" },
                { "az", "c7c652a2b1f778e900417589c53ae62b0b41a114df274e4992f49396d2092a796887b63cdf2001da197215a67b1705698ce1446ebb3b2be73f115738c0f4b994" },
                { "be", "5322aeb1400943074272069105d9dc68d995989944e92ba7bc3ff253edcd2c67c9c99b23f64fe59dfe9c0655018c80e6d5e91a82a5a39b70a1276d12bf1c3914" },
                { "bg", "b034925eb0118002b5f4aa5b4d74349ed74412dc5010f9cfa76e5991cdc55b8968d53c3b103d50e56e8ba1b0078529a74fd2b9091cb6023bbeb3369f4caf405c" },
                { "bn", "08c1acfde7463c3bbd94afe9f8d3d836e88aac565c1616ff175cc4549db4b8abe80a0d2303c73f5bfedb1b3425055602d372b399e1e6e8c3dfce35a005ac8cb1" },
                { "br", "71e2bd864ea9f801141a59882548f8e6448c6323a333f42d064338616d8a21ca7c1a852118fd6acabd8f4fa7b7b01d789ea03ad7319049cf0091d653c9fc8698" },
                { "bs", "bda296144752ea4baa132add89c7bbd7bac554d30848ec84000e94131dd7b1ecdec67e158b0a8788123f2f4903773d3e71cfc0d234178b8bc0244d9266bd9c0d" },
                { "ca", "97c8f6a70910c5da67b67185f328378cc4031a6c69418cfc5d9adda70ea2b0ecc17e7ed246be0fbb41b1f30b24c12f287dbf74ed6d96970df5ad5504c345c274" },
                { "cak", "285d01961469d3db3d380c605bb735608cb6a1b327e3ea0ac22303ced97327c8e5920de980f34fa9c17c725b70607907aa32397f58eeef213e8ceba70da14a8f" },
                { "cs", "4fe540b7e147c02cedaca40ac11c4c91eb7d014812f1dec06799c7b5d8090cdb062c846bb23be041dcffd1beef544376ba3344b8f0555e6a7c4dee775da9bed6" },
                { "cy", "89f139526a4feaef1bec35e6938cb3ef12c5aa52410dea3cdf85683e07f77fa0ce692b4150668081682f29b5fc15849a7753a5d20852bffef671b8912c2d0078" },
                { "da", "310ebe502664ef799297f08b47e4e134c6b53660103cb961196218aff79ed96f6033c80b0eb3804cc836294233bc07f0e1cd3f269483e62555423b28c2e67004" },
                { "de", "130b668343ed85763153c0b8eac4cd05218a742fab53592c5743296ab1a2b78d5ea5d6f060ff4471bd74c6313d19cb57cbe2fef91887c88ee2c4ed180be091f0" },
                { "dsb", "93cb2931808f1ab93ae46d357556f2899f5b242f06be2196ca761a9636be04d8134dfb450c1fea4b66973142de1714735ed29c4e4313d44a2fc955ece6365893" },
                { "el", "1669646dbb52b5d3d7c76fe7263647b2123a8b93e2d083ce17a19c047aa784a27eed082ecbf34c35d6c0e4d49ad052c8fb6668c7e68ef4f1944848a23357631d" },
                { "en-CA", "a42ee4bca4fc16d0c691d7eab2e1c4ca4f04ef5db8a3937db67d3b9373135567dc7808222cd2857e405b621de30958c8540426194be1cdeec43de2f4ba44f16e" },
                { "en-GB", "aebaaf33d8fbc00221624a26afd021adab86ed9e6c6af212476555615e7081cf28429f45aa6e931ed3f4260aeff10d713a922dbef2af915ba57c653fc0b1ff2e" },
                { "en-US", "1aca422d8c96f360b0a31b32dbba3e3fb2167435a3ca406e1354ad61d419050149371b8097e1463fbeba03abd9963571fa6fad6f088ce64b25ea6abdcb97775b" },
                { "eo", "a11d433a8f95fadebfbc767f98457e05edcbb0202a8b5aefbdad837e6acd0bab8be6765914f5ae664d739de3b158f1247a30449bb93b6ea2fc0cda3912c2371e" },
                { "es-AR", "338ba299e5c1dd17c1b3ca36abdbb5a51d6b0ea16a88016f6b1335d2ec65e40e2e1082ab15573b3817913805ec9acf2406c9717cccc037d173b91348b22a20e4" },
                { "es-CL", "8e3c87a9da7264bbc797a3834500096326dbe0e9985488c8a99c25f93f2377b914f68bbc9a2c186e067deee9192b85dae10976bed152c94c3dcb0342c8221414" },
                { "es-ES", "35bb0f3100e537c0153d873b82173081552ae0ad1582f12c410b68176a4c8e4ca4de979fb4578ad57cab7e686391a478908d548f1e34df1eaebb18ed4985415f" },
                { "es-MX", "f3ea7fa4f2b1127ee3a02a5cb57ac95301121199454f74802ffeedba0730372a835f691e0bd2799b625142cd08774ee13468eb867ec532e48a4972d1aeed04d3" },
                { "et", "df0e80f7464392fa93c0869bc727ef3582c0a25ff90ef3cef4920605ea48675f536b95107f54345a166dc33d6fed848822f822c9565eac104ef2eb5adb489c5a" },
                { "eu", "74a8c540736b771ad7a85446d9efe353419bc07a7db1b950585e922f1b37a3350b4d8f409fcc870b620fc1045acf2d620e80ecfa280374c8fe315f2743b07a36" },
                { "fa", "9c11edc26703945afd370333488eedca8545eee9ed8722b45ac1024bbc15c5b967b03b64f0362706987420efd63ed2b9dcd5fbcdaf7b172b29e6b92286b75305" },
                { "ff", "c6680f8f135d2ce27b39469ef5977a824b09d0ed0fcb118b78bfb2a7c96f81a8e68d743ae2593e91cc0368584340c3ae57136eabd0034dd1eace245ac4117e4a" },
                { "fi", "3a779e63555c7c3c8a8868ffd86eb044399ada3f34470199cdffe81524f23b2f19ff9228a357d2dc3a6195a761f23fa96f6d97f0f6281133e21236fa3d8cb6a0" },
                { "fr", "c9e1a8f497e893611b3b87aeb50d4010051bf43d5dd10983bcbd5cf93830fffab904e0aba56f8670e3ddb96d99cc8dfcf8d729c4000ba554f6045757bb94c9fa" },
                { "fur", "f8ebd8c6056d8e75b9a47564d5baa1d287c781e3d0d578cfcc573c0425d0f4739eb78acf25f4e9216dcd94c5ba76539a5d2248db0204dcf5425079f8d1baf159" },
                { "fy-NL", "8effba24257d5708afb569c97d79042beb64beb5016e3d159e5ca285812ca2a508bc52cd45a93bc41916da3173775b9c86886f0fdf3efb8baab6db31b019f781" },
                { "ga-IE", "ff9c41539ef4daf7791cf2fffe2799f257528e37a02e636429595ae62572c28760a064233de30f4ad8cd893b98ca181651a9f403d313e67de6d37d556a579e5f" },
                { "gd", "548f16d5e998625d650c5e661fe8fad4a4097221294ac495110ffa2804824e6a351da1423d450e4f559f6a923766d0c48f2ab0fd8494d71cb73fce4baa625c04" },
                { "gl", "57edca28cad788e002590311ceb9198b1d3d7b9fce010e3ef24ce9c8192398c1e8c8281b635b15a3edb86148644a7504adca7776ecf4f00a28c08bda93db5d94" },
                { "gn", "765e5b36497bdb54eb011649e91a9c1ccbd76dfd83ebf4270e0f68d97f097b30aa7decb9892feb362476d836df4ad80e55e3b606fbb59dce1a6655c4c6e5971a" },
                { "gu-IN", "c25e1195c494af6257cd851d4d68253a4492bb63a724417baeaddf54fe342ca9d1c2d985aec4266a05f0bd15ad882f25f2051d099f1dd74953537a995044f0c6" },
                { "he", "67925ea1220c66ea4ce0e348f6f1aad8447b2fda1f7ff80e714343cc628f3334000559956706db88a8468e4b317f835cf143173e6b2d590e0edb4d585d32ae3e" },
                { "hi-IN", "dec46c09fefbf9436b440ee7362e2176a21b8e45e016e15dacf0e38596a85aa89a583713c8d69e5c27363859dba11a29ba6ebdf889b85f7f59abe068db1eeaab" },
                { "hr", "051e9fd3d774d13d5613728c04824e2e9018e29b38279415832ea84f2b0b140a6329b14c8e40952a3d4192828b78355a86099ec35852baec56468aa9e147a9a4" },
                { "hsb", "537bc6615fe7aef6ad227ed8ff7d3c875a759510cc825a8cbd19a2467ab11b78ac0d7f0ed5adf745d4578a934f8e373daf4d9a333429e1b7d8cb5194eac01932" },
                { "hu", "055dd6a7326e52e97a2db34c86656397968b4a9378f8ee9fa4cab71c7b13d52b6c5f0fd330d0e18e13c12042a2d6dd4f6922846bf2bc04f9a42cdad5470e967e" },
                { "hy-AM", "fcf36843ed4666c7cb61f733abdc5fda82b5fd2086f7e8616002454a788954eee3ccbedba0c491af84faa5f8952dc3a955df0bd30173590b1b94dacefaa3c305" },
                { "ia", "75c34a96e055df5846af63610d86a7ddd4be7d6daa484ec032b6958342a59f14916127751ba9296bb97bf78bc33090b2948c42cf83f9722ac0b14e76fbc23f7d" },
                { "id", "ab3d84e6bfdcf8b2737cde2d708944886eb6de71171f7c68d9c1d7a6ea674755b3ccec3b04534da3f66d39467b6a49de7b83fee6ad9214eeea866080cc820924" },
                { "is", "3c6224011c46a5250cc07fe4e7c7b1d88618283ebe907024bd7abe64f0661499104c5e9f96dd645881a851ea5c3cd6792a21f0d907e23d3958969feb75949f54" },
                { "it", "46c59c9b49739af06974684db4c93e7d07eba000715d3a69a3b094643503ec58d3240262ebfa382bab33be03af82e53f884f571e9c19ccc1832a42c484cddb2d" },
                { "ja", "d8c9392efa16afc79e097f9285c9e4d41f8ebf7dd4ff6dc163e88149eb1e3f77fbeaffbb13a73b6919a0643558dcdc26e344183504350a81e7f807b66a563229" },
                { "ka", "80c58a3f411156fbbec1697a69a8513e4ee7b47d44d99aed26104090643b4fd7ec6dd3555e9aed1eeb876439eb0a20a79faaa2296afd60d999cb2ee3bb4e0c36" },
                { "kab", "6c8a9dd14efb23f0b052ca1ca8278e68d33b836e1cf8347efd29d89c5f66d9c64b28a9c3f3ec824f8bbd08177b63b50405fd10417448ed6c046eb8ca7aed4bf9" },
                { "kk", "eedd60bc9baf09d67bd909668a832169e5f2ea8a711686683f112a11b12f2a8f08041bb7f9d0cc9d0a97709be5f16d7a1f012ca52d1e5332c13032066e85bb94" },
                { "km", "478a7353d535b113f667da5ab7316006f826b6e33425dbeb832c36d70c2db1ab542c884a6109a91715febbb2761a7741538ce59726f5e68de0ddf5ab0e197dd6" },
                { "kn", "0100abe6b59fc9104e76ea6fb5cec374a885fa12c5686113ddd9962a3502030b78a9e6e2dd9219b5ae42117a245cfbb3afee72325961b3061d748e9220bcd475" },
                { "ko", "933aee5cb792c6dbe83a81e0532b9ec59c03e49d33832c72f61e769b10f8e4b11c4699398aee5cca1f6f97980140d8b18c960fc901c95575323d8ade0383bcc6" },
                { "lij", "69ef373cba94702cffa1b296aa2aca51c01b347ea86d2d16c5a27a2efffe47dae2d9dccfa6723e69bc119b859509333bc64904a410cfda2242496e2eb453da85" },
                { "lt", "60634a042c255685d37f3b6fe9e5f14bf07cf4934d6f82e5efaa7d83276723b747df6b380451faf2149e8adfae5a874ebb52edffc70a4528f99b423562fbbd23" },
                { "lv", "7d28a0674ebb6f358437af6c783f8c171d2f04b97dd65b19bf4f5d0fa80ff1d5937b66bd094ebfed8f414c05bb384177cf3bbedf5f57c790eeb3b1bea5d50825" },
                { "mk", "9c55b2803d59a940666ddd6b6bf0f2f50d022f0d83a10ed43b674554a10c70a1a3071a44b954518b59ab669e2dd1e8f54314247bd42e106473598380a54981f1" },
                { "mr", "1b4f68e16c71e0729b8d252a4ea108b7bc356764dc92bb6473b8ca00b317e1ad53eee53b471e366acf0f99904d7e63dce1f347e9c60ff35d4e6cc182e1e68df6" },
                { "ms", "af5d6587e4cd86bf81da41293d667201e3ec7e59a9f9ed6cd41e443f0d7e2b6f31e16da2c1a2282db02598bbb0d088820e42feea9a300f0b8c6261a3a9dde050" },
                { "my", "bbe33b6c54d4176d2292f7f6fd47e2fa35c4e6151309d150c56cf8351e2a736eba8d0f2a87a27613b4ecd9ad83dcaf66d3079d013da882b650afc06ade46cbb0" },
                { "nb-NO", "604df431072067dad86e9e4c8f1280bce93f7001aae7ff841d81c208909dd1f53df60d6a30dac1297b6b0647ddfe30ebeb24d1d0488aea2d99a6c12fbd218767" },
                { "ne-NP", "4375cc1d796f00829320cae9c6339c565b393be10d832bb974cb8c2abbe4b2ba0cbed0315fa3fce80ccd44f119d16c996b93506efbc8e8d52ecbe1f77f8abe69" },
                { "nl", "2b438042b99a4328f5b470c84be09e6205809331cb81d624cec2a69831fbf1cbca8c1c9134037a3ade9fef990d05f2757c65ac7b3537ea23803d414e896c4214" },
                { "nn-NO", "b3a27b207b1c838d713ae36e955495e9ab703d63d31d853a924da260aec0c91c4be67727c53069cbf03d7b0e53ea2ae22146c5681ff32a91aad35c0a339bc595" },
                { "oc", "401aa6db6683bd9e0058b1e7f061d1ddf7e012888fd984afad22049c9f4e90f97334576779f11a88f8d8a8e034263bb32d80751e2af046f98637b687de28a3c7" },
                { "pa-IN", "1b09edd40020782bbe4bb74079b931a6d94104185159bf2488567b90bae34a0394ec2197c620958b5f1a77631046c9e3eb24a38fe6fb9e8cd64d9959068c8056" },
                { "pl", "c00a6bf3e60c6715fb0a8505d12d60f1b75d4df90f112625a335e03e1ff8a7f082f2e0842551c0642171ae452099f5175765314085eb557b1a11803dc5fc6118" },
                { "pt-BR", "2cbe52d8f022f8c10e79673de9ea874dab09631e4c11de6e318c28f63cf7fb43dbbe3954a483eeb226f74efa435c4bccb78a89915ea09db94db5e1dda65c125d" },
                { "pt-PT", "be680762bfb2eebc269d668678d710c56298d457d1ce0cc6ea05b990aaeeb0458752594169438a66ee0bdfbb8d04271c675a98c9d39324ce65b135f01ee84002" },
                { "rm", "ce604aa92b98201fb40223af474e7f6e1befb85501c2d03b996895c9bc31c8c7aca9720936a93892c042878fa55c243797e003a7aa30dc622f2b1cd66c28b98f" },
                { "ro", "92393cf54faaf415d397f8e0d070d6d213ecfe20674caba0224ef493d6c66293bea92026d8618860c7bc69480035fcdac3d34fbe3dd1bd4be33ec49f4d0b5af7" },
                { "ru", "b36db42528b8c95a787d2724f706c7c9b29bb6821e9fad62e7552d4ba2a4b47e8b68f65024e08ddbc924fcf539c2983e0af4702852161e43aaccedc57ce72152" },
                { "sat", "0b295c8a2f2c0d32d10681cfd37a9be1424675d62792c0d060a04b01f3845d85a11a67ae520399e039f6adf5b27e80969a95519d5ae7ab289923ace909401d6e" },
                { "sc", "5d3a8dcd1cb6b052294a9cd89ba86a371ced4a7ec1dab7b8ce0c5680ab118587a5e9ab272f8c7d3e29b215299d394c53d567b29b7dcc5654e41174bdd09ee690" },
                { "sco", "7baa02c605cb634349b905d2baaf1cb3d8b0cbf79825bd5934eaacaa3ea6766195b36eb74fe37dfa9a3ff7b8fdcfd9041d0826f56e051978c21f16491a0256b4" },
                { "si", "1f9f42c879b74611d6455b78ab1dff3043a47a0ca2957ff29f2f3fe352f224b559b78dd5f593d34c120e89cb92458d865b3b2af7b292e8905477fb7895bd16fe" },
                { "sk", "a5977ec1a4c9331afd4b04c65712cde6ad6863601af31bd89e15d69ea8f54579b7438309ffad5b5e95a1df900e8bac082f865c52eefd24f1f2dbed4c6a46bf3b" },
                { "skr", "8049163645a703dc6fa8515e59af5d3c4553a40df1a2d62320b7b721f3a6520b508b176a6a16d013174c9d264c69ec7cf6c2ecf60b75fff35b850ed96a1e920e" },
                { "sl", "7b8f7404185c8fa56c964e7d28bf5221f68cbde1145797a410e138b82aa99adb71cebd2dec0ec96269ef542b1c8e6c67f690ab22295b72622b49f11b2072f32d" },
                { "son", "edf977663bd1e5b49240d9390da8154816ad16a118c36eb49328a37e140c94fcf68241b89715deb31913ef4117ee07eb1f190c94a4640c9bf5e94cf27e0d6753" },
                { "sq", "d17230c0c592ace4e9dec5ffd6a09eb57421b6924abc5280a3bc26ea401e20d3ccf04cfc0de8e1194928fe0304553eb94396b8c75250384cbca4c73ee654cfe6" },
                { "sr", "2fae423883ed26bd8dd815deb2077d2f64f1093b8a9b1c6982062e2d01303f8fd4daff5f974ad3398bd4898f95b1c5655af0b5ce7535fcd21ed9e90a349f6b67" },
                { "sv-SE", "9a47602e8f302acb7840f4bb4e7643f63be64c31286c79755ad00cc4963d48c358b580cf126a5ba9c18aa312c2a07a76016cb2452bd3bd77a8c70d47cb0e523e" },
                { "szl", "a20556df8fcf3c8f0df42063d0a1066e06a64d4d31e95059949dbe2f73a0630f0f9e2f7c51cc05071ca55adedbf141521aeefd8b34f94a57acedd52875959e95" },
                { "ta", "aba7c8dc0968a5816a33ce18cf1bb9991da7329e14f7d8723df5a24c4c9adaca3db681f5ea693416deed19358900427c0467ff69c6ba69470b6789a69beac04a" },
                { "te", "c84f7e52b5ad0f4f59b37b8cd94a95517b76c3c1b3d6cc29540e9b27dfbbd6f04b82610fea53226299eb97ffe865dc24ddda9176a752b14b485c6e58742c0d84" },
                { "tg", "1f10d602efd61f1eaf965a52c8de9805a2c1214ad71dfc433842412fdc148276500b6f82512ae762536492bb52511c33a495b127933ff070b2ae0cc9ac8ad0e1" },
                { "th", "3e8e274e09d0ff527121fc9d46adc39d6e45432cec005aa854fd6db4c579cc410011f70adaa9f96ea59175bb71b6c9e70a920b461db820cb72b6a7ea67a91868" },
                { "tl", "af9a08b0e08c3a5de3c5adf8a1727de592c73061dee070590a6cd461676cc95dd840eaa476711b77d9c8590a19473641510146a3f80ff661069149547329a4cf" },
                { "tr", "38f821d0a29aaeb50b847111feb29f3876fd84ebcc0cf8df1124d5cd12dbfc2bdd5e3df0410c57cced76ee7461fab07021741562eeb08890e1bd6383d1a9160a" },
                { "trs", "ed1281f9684cd7f6c5c3fcfcb08959250724cc2f5502af4fb9a8371fe8915e31d574549b140a1e183ceb195a1d234bf595b9fc89c12db88c92ba640c673f4971" },
                { "uk", "6caf1a1b14cac446c0445f035457a4a1f0a79bf5568bcf05140b7ce3b5d66c6674ed984d665819318cd5ad024f491585395fb6cbb1058244bd0550961789cb58" },
                { "ur", "b45fc4db248d2d68148eb8c573e13eee19dbc9c912d0705cb406f90047b8c27b51076c6c4fd12e5e966c200fd557cba0cf3de871795aed21b5179efbb6b96d1d" },
                { "uz", "b85a8306e03d5fee7dc83a5958a058d9e4d390d6a7e637f3fcb405c82bfc2a1b1701fa6df24affe3450d02448c7a4028de4f93680d8098eb7dd7a63033fccba2" },
                { "vi", "acb23b1adb74770ef1a0d8e84d6e35855d63cdd9ff2d6d98eba6c9acbb0d9ef80f70ac1e86afcc80bd381f4bb67de7767ea54a712dc059937b75a3bc3115635d" },
                { "xh", "d8d9eec7f39f05f11c6671df23f6055dc9f8ead133330d8bff40dc1d0361a12a8e067fc06ce6bb3aa2fea04223f074175d9a01caaedf562f7bf28db3099f04d4" },
                { "zh-CN", "c913bc767448b0d47fe0a21ad09f8c5381ddebfd298734fc966f8e5906a79f7519740bc42779f3e36924ffc5c77f6a391c9585251a1b9dc615df1ff57f5488f6" },
                { "zh-TW", "9ab52d0d66d6014eb2b3644ca386f687b5bac17b006beb75aa6795af087465ceb06be7861b05ce1783461a4a6bdcc23d8bf5038abb72cd1754cfc912c4c2e844" }
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
