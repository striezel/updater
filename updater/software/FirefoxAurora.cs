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
        private const string currentVersion = "143.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5cb5af59e41605c7f48bf76d44fd37176cee0cbc800208f0aeeaac83e87d6b3d512ea9087a308956752a77d316e0958ffd6c21fcde1f62330011d9134ac2d3b7" },
                { "af", "702ce6708cfed540a20ca76e8b17d56a646ea3fbb02166107e7c85b55479753b1f99354549d543a2c67417c927960d7b8d959b21e2af35f7558476a51bd203ba" },
                { "an", "4a2e5e5064d82175bf288c7ddee8489ea62df0446d89466585a3a675ee658cc37433eddec776e21dabac2140e2254a302f3d7bae40cf5e0116a5a303e6a0e4ac" },
                { "ar", "20054cac3533e4242872d581749981423c0a70ea6b3362828d8109317e2051f562d335b566ebd0fd9d6cbf2c40e8fe30f79951162ea9031e6c7f9b8ee923501a" },
                { "ast", "14a7b2f43a140bffe4fdc00c7fc1c4321f8f297cbc660d9016a9f4d771080b4fc85cc209ead9f21b738f25bf2a0002299bcad07eac4049d269fdb421545af625" },
                { "az", "371e3914b610f8cf65284a952ce7d6a1d860ba8122b84a734631a0b77b195aca66890813c9f3caf454bdd08d95c138749db960e7006c8ad60cd2be7b62a823a8" },
                { "be", "207c21d1fc1952fd1745e98e70070c7d046b2a32043cba5ca108d72966612c7f89721c1a47ff7ec1fe01b8ba4dde87582b64d226ac3d51c2d4f96c059cc23a82" },
                { "bg", "907043c8102802640aa24394c925b8963932a8877c05ca4d8096e39692f1498557116965e9e76c1beeb24a1c793ad75de7d971199ebc48c5722a9e31458a88fe" },
                { "bn", "0fdc6c032ce29f1d9304cb161010af0ea6d9fffe0860c359e73d729075ef861526123fc8087cb35add5ae472e6a98409841abdef2beffd1fdf7780ce6d3cda9a" },
                { "br", "ca09a0f3361bbb8dcbb7b6c51489fa0d52c22ee15077c473c92a2a5ab259f075a0a92524541846038cf9f65ead599f59e3c6644b7e99e52bf6c341e5d4472dd3" },
                { "bs", "cd41ab38896bcb9c9368361881f9edb838d44ed7e11d0a35116f3367ad1073c777e545305e544f64cafdc9531c3865d16f2de3bd5e13fe7e4ee1bbf000971645" },
                { "ca", "2e638fd4f399fc1e8914fc0a22f99bfda3c8c1de84b72c54be59fa2694a84bec12a845e34e029844965ba33a7a7199cff0d67c47d8f0246f39b4d68e111aaaac" },
                { "cak", "576991c1aa78570af588bb3bade7bd30cc1f125af9ad0dba609cd74010fdd8e4c7bbe47ed33656d7ecd21000b9ada11f5e5b28602f2f79a206a6e32d572b4121" },
                { "cs", "96f2e13d1992de666b3959788aafcb02bb8ebb64343a0e30c4f9476458274d77a295e1ac9dd97a05bde6a8392f848f5b3ba940ff1cf407461bca97696a7802da" },
                { "cy", "73e1c1ff7b89dc9c94ebddf503098599f0ffeb3a0932fee65736d686c897831d1f8195d0db9023666202595dcf239ca06aacb3616c31f08891edbb344600a83c" },
                { "da", "70d36ab0a4e0ca3311b19beba27a6b9e6ab887901f1fff483bc1ffe9659d04c98d9ae3a4f03895cd25e68e206b258981037218d9c56bbf41419f7ce041a22a89" },
                { "de", "f85fb92d5d54a0f1556862388577613888262ab525e72c3483b8eb10e0c456c19f531cf6b4da6483771f9aa15ac74a2037b12e0bd28e4bb175e4aee2432355cf" },
                { "dsb", "43b285c6462d7998c0d05e3d341479ffb2e8a6858c03c9a67a604dfdfd45dc9aaeb1c414e9cc79981c13eccb0f134569c244e671edccc5fdd57a51cd8d61d2ec" },
                { "el", "d1a721681f503e455f686ef496e7b6fd1ae7b6de96df9f09e3bc2d454c1b75abae8f8cd1b7799f66216eb9720238157f1c5620c93ec0d617f259bb639ffeaec4" },
                { "en-CA", "8525507bd1d36426030dab18dbe4d878185e4f6f207fa3580f1f66f0c0861201e89e727c0d7e4a171c31e2ae45a15d7b00af91bc401ffa8212a6b660c41b366a" },
                { "en-GB", "b09d56aa8aa722bb90317e62f9ba461cd97992fcae35c32d10e523a4c52675f1c5b3868ffbf3b1bbddd497763653a7acfb4748778ae86e41d87d8bca3439f825" },
                { "en-US", "29ca63f1db4d1df490be09427e9a8efaa4c61bdc3ce35df6b87abe33275bb741e13734db65cc16e60b9a24f722415d11fb3cab5119cad6d4f48fa03cf49f6ba0" },
                { "eo", "e33ac1264b02e0e41cf250e3aa671cdc639bf21b4d4851a0dc865281b7575cee25e3f8cb3fbd01c369ce9b78cc696c93cfaa7a43059fedc7ecf7159d43b28aed" },
                { "es-AR", "6e3a48f4f0816199a604f3afbf4816025496180f0b16a5f9f43ad5c3617cabdfbbed80122af235efa8ce4667fb6abf1fc3a08ac26a43dda045c9e06b17201790" },
                { "es-CL", "f5db874fd27d5fbe412fac538e7afb7f83cbc26d4b24a547ec0c25abc4bc189ea5ea5c652d1356dcce899cd92e3af250421c211b6641581dba47f82e3da90ee8" },
                { "es-ES", "a4e5194a238143837d352e3061afb390d455b1e428e0d4131db57f8d78518de8e13adce65a5223ce9f3d144c761d6135768c69711cdbc9df176a43d5282c8755" },
                { "es-MX", "e9bb6de1c1ea5e805fb576bbfca1e80bb27c93a3bb82dd411da4ead6c56b23e5ec33059ed186362324a0ed6ce86e73de8353b854e9352c292df27a83dff8aa7d" },
                { "et", "c29bcf5f384f8795c050479f4b29a64ca0c3f4cbd7840bb0ed5b3302a22a60f5d3b71340091d66577bc03763fc48b195f30d97526eaf52516f323f22f12213a5" },
                { "eu", "9a7d9d8f89fa57775469d4201a088fbb8c6a9118c82c37aac4ee840cb7f7f6a5701ff1c14da22aa5024c890fcf152c5e7ed01415c383b5048a418fa9f292372a" },
                { "fa", "2be8fb788eb4250c8f817f5f530324bc07aaba48afd1d3edb2fb816d2bd7c9375c8a64a9700327767684a5cc49bde96a69754d0cb5e644a04ea291c2ad22d548" },
                { "ff", "0a40bdbcd6c508ad7c9e9d182d8b2cdf8863034375f9f2b6e39c4ed4396a8cea8a565f821618e0ac3fc0120c5d7db7601810f5ea99e9ff4c1ec0a1f92e452c2d" },
                { "fi", "d7228c913600280b26ee11844782db9201d80c6230ebacf1ea462d732ab287ac6e05cb10ed67c794ad1b1a340e9908915c2ec88fdb62ebcab9cb900c0edeabf4" },
                { "fr", "f3741ecde2c7dda6b758f5fa41c4424bbe2a6d4746a6de2e385b58560811c60872188e63345408369377cdec902cfc1da5fef8aacf0ad11b449bd84f410686bb" },
                { "fur", "cead9a0e90e1dc8615439fd90213469cde7692d9993d1210bc0367cdbbdf55e3fb7bb332a99e20651adbd1cd883785632edd74a6f9978b538dda79b2ce68f6ed" },
                { "fy-NL", "7c34406b05822fc812b39bf5312ba59861a15adcfc983828820827d1365ba3acd3c5de361c5df078af2561a716ad9e592a7e27e272706e2da7d5ea608637ad9a" },
                { "ga-IE", "58cc8a1db2b7f3411b11eeda36f70599fc716c591c6ac529074841e998aa57affea8662ef2f606084c958f92914601407382345ca167b35a3681975fcef9c70d" },
                { "gd", "11c519ea1a30e902fcdb8175d2f6c5e085f27d4dc93111df8911a5da1d83016e941fe1c405fde9760f9f940939f2eda4fcf704da9824effd0f67683b84f85d3e" },
                { "gl", "8aceee7d5e2032dd3ed9b044e730eaa06973de9e3d8caf341e816bce24cab90a47f40371d78d66de23f98c6d477cc6145b49cf8499d3ccf40b5dd95975253284" },
                { "gn", "b3ee893a30ad85c6c0f98504530f6f721efde70c6f57307b38d5ccef578a879505e52575ad22068894c812985939c799595f19df7e1f64c7701c45fa47f99f47" },
                { "gu-IN", "b4d9d136b3efaa68fd4bd88d54afe195225c5a68381b6a480af7818c081a02d1f0b7fe934ba4e761a96d426b3fa5dc8a7271154c51d9f50a84ea5bc46bb058c3" },
                { "he", "4d288e5bcf19219025866882f74d1025555ce7f90c758a99f73be95e03d5f34e9c5e7d532e5a0f654bf5f43c250bc7e0eaf90f0947677b3290f8b79637265267" },
                { "hi-IN", "a8c1579259f8e9edab5c0d0daccfa44284aac2ae8f1062285791740e013b702ad1bd9be428b2e411347bdf2bbd924a1f7c540483228a6d0a5418c58a324287d2" },
                { "hr", "a5002808b200d56d648f889524ef22a818c33848de496ff946da25409ec68c1e46029f702f59ce6da5e13775806b83768fea8b39fb1b633022f8a3ad0648cc3f" },
                { "hsb", "c902b3caf72821cbfb70bd467d003ffde6fbb4f9eb22f0379b3f4e5fb76556fa9963f5df03a492b99ca2f119c3903e88eb17e7eb973dfb7d0230e9d27e32248a" },
                { "hu", "fea0e3d78b9d6602bc0ce31009bce1d03cb80025d87cbc8279a0f4773bdcbfd16b112b0a3c8d1aab9d433d66cb57e50e247a750fbe2cb9584bd2a81d7b0c137d" },
                { "hy-AM", "5468043c82d21c8fbc6252b0f26492273b486f6d0daea3a10a850d52db8a6ab600c36f15d3eb9fdc425e7ec541bcca5c9accf3cfb51c6dc3b23193f261d3c6b0" },
                { "ia", "8c95f5cb7bc44d159254f574f386422608f7bd73bf8c00ebc2f9ebef8cb75bfa27b577ed2a4e98e9cb8bf5c2ab3d805451a30efcca83023f14795056ab297e8a" },
                { "id", "4ed0c56d72705f404063c44549f1d8cc20497e44be372096f9fa98ef5c749232a1219cbec8e1c5705fc4dd9d694e23c88cf9da54ddd36757b4dc7e75f8c87478" },
                { "is", "fa80a23225a1eb13ffd0c21c4e7f9e776d37745353b857c18bf55ddded0867ae420bba9c9fc4a767e62897a8021ee80491ecde8b90986c7d75e6157c9ca1488a" },
                { "it", "0b6158af98b5b53cc8d355d62b7540c8b0ed1c915bdd6326c1da335faa7a89f5b0c4b6274fcf0ccd37f541882622125ddf9f5c06acf667a9be141eac0e8a10a9" },
                { "ja", "f17fa95daf06ddad112be5a1b9cb02f19b37699b89c054e56bc5f14f0598f73db57b208d324e8a3b5ee345f534ead81c6aadfef2bfd764cca436b739a31cff9c" },
                { "ka", "4f2d2adc72c27a07113fdc1cc396ebc0a2d6dadfe40f19ffe6285c0a89face639ca2cf19a498d4835174d58970f17bd4de62b5883fad0abc8afbd7d60a004eed" },
                { "kab", "37ffb5acb696561f127b96ab1923fb0737fcdedceba22774f0763fec9be3d26fc3183f331c32fe1ce61e2b0747a518ec4def46240eb680b9c518093b9a64dd9c" },
                { "kk", "ba84d62113163b63a9a9f8ea50bed9c095078fc79e47bc71984f8cc19034e0006d2a9b838b717d17f73736bdde8ae00281a8da3e03c5c6b37afd4b64bdee24a8" },
                { "km", "3b1294cf5671aa6042750dfb10f760613de2a6da2f04c3fa013ef93385aa7cc5cb533f63768012b344d9b1e9a3729b45ccfddba83cf8c3aed413bf0b88ecb93c" },
                { "kn", "969924e7c5d51f8fa00735a42cc8027c2a8d1d9078f081ff847189375a1d7732d85961d576c0dbea2af3c1b1077a263cab7c1066970a040cda051d12752cb6e5" },
                { "ko", "a85af19f3d838ec6dae83027611c5bc5005306615ecff7e9aa14c4087d18ec12019a6bacdb9ddbe6c91fa8823c8a70516be452b5e4cb60cf87219574dff4b052" },
                { "lij", "3971dc55cd1086b7f57bde7e08f77b55b2bcf33b426269debc945f1423050889affaf738761e2990bb9a51b382da7a4de541f33425b5680deac8b31765d6e571" },
                { "lt", "997dfda3fd02ecb299310109ed8ac25dec2390994f9ae9c84ab7e2ce702cc17dc0c439ab35f3d606c50624609a3d7d42f4a7eab1f9769edec14bab720321c6e7" },
                { "lv", "3af35ee9e3ade48321ca62db43fd87f158bc0dc110f60c59d232943214f14a2b87db88cd66b2497a508cd4eb89f012132814181bc3e3ae6d37be206b869499db" },
                { "mk", "fd6bc0b73ed580f0698b1869ac96f34c4de256270fd6148e530dbd21ffbdf1364261c9fdfc8f63f1301c9886cfacdcd88d11c6ae58f9376f8963cbca6117c435" },
                { "mr", "cef0a077a22d35aa54bbf3cad46a7ab12215a2d1833a0c3d3b728e1c4350fe361690862c3ad0d0c36a5fc398bafcce1d8a2872fd506dfbbb8ad7db6f7d94a827" },
                { "ms", "fb9dc7e45cc676b89cc4d8235e3ea2645751ed639bf8622f4d6eaf89db7b274f6d532a4cf46aac42f247fcd9f18ae7430dfe097491a0154d403df88048eb6f39" },
                { "my", "593f2b16b8632843736ba1021c7cba2bcfe6669c31f43adaa0935ed7a3bf46b67be1f44cc7ab60b471bf8b7b6de42ec779de0bee5b388d99627dc6002729b61a" },
                { "nb-NO", "fc8c3f1080b67365086d4af402c9b42eba173019a7b0fe485ccefb4600fea769f96b1a545a1f48937f171b7ac1a1ee63cedf6d309ac6e018f0f3fe33ce19e762" },
                { "ne-NP", "35d0f3ea9b0e447fc0c1d8deda3defab3703899e22a3d494a10b8e3ba5f28cc4c642dc04668216ff6949c76c3076460c6d28ff481e14fbdc7c82ccb250e4973e" },
                { "nl", "2fc390cab636c5c1d6b7322838fd76f56ffa10e5d08ec725e7104851a52c4292fc8032df3ea8709fcd0f8ea28bad1908b0c9a6f28ab7905e6d5122d9d0b77ad6" },
                { "nn-NO", "b7efb1060f4948fdd474e6b72436b673b896d7171f62a0ca806b7b36eb8249d9e9b1d99951421be4322b067d4a559380b47c609dda644f67c03c5beea88ef969" },
                { "oc", "00efcb11f46e8399e5e935970d9bc57a51700eee4a26f962cd1619b81611cd1c2a45b3d1c06d73516409f295007d9f89caa947904c050fb27bed5a065cb8244d" },
                { "pa-IN", "87cec01fb171f6a9c13e01bb8dfefa232640a31bf7c8cfc57fae2075886d51867e59ab013b0c5a333857fca0ca7fd75a0e9924e3f60e1bcaa3ed50fa810c15b7" },
                { "pl", "97436acaab5cfddbb300f4756453a8aab54d48345b1adad0691e430c8e0be49d98a2d1bd6c4ced785121dd6da6586430de9701223f9cf7a9fd95569b16fdf22d" },
                { "pt-BR", "8d182cf7fbb185dec6cba3cf5c496e49d9605a85b31f0efb93f78cc4b4478cc5f87d6e1f222079cf2c36dd4ced439a3cfde89cde9f54b148844a377ca76f9228" },
                { "pt-PT", "715626d4f09414cfdc73dc3c8db5bd2b15fcfbf26fa7d1b6a4ab3f1b4bd0bd506b1942a2dd5ff5b873e9e1b435f7a6f751c8871eeef165b536089d8795985ae7" },
                { "rm", "4e4341e2bf16295abafc861ed57b0e9684466af8d150fab8d1a0f33dbe1c4518788f9481d1df044cdf96217125d2ecf2811e321461c38ced873512d3a09bd63a" },
                { "ro", "2771291c6735d06d5bb41a7c6c89ec0f03a8740e10ad514e02dfbd540560a4c4a8f6251fac0f8db03dd1ad846b40f2c12642507d319a4b921407960f50ea61c5" },
                { "ru", "b2b5d95f67050645a58dcb024b3f0d46beb7bef84df6cbaed72162d82d24d8afb28d0576d3e7c8fa98f142b9bbd4655f7cdccfe0dd5445a2912c0336328bd76d" },
                { "sat", "718b5274b9b59efb0923cb3ee39b4026a4d95071c68ec6113ca24f6df05866c2ce63dd2f07339b3e925a4a449a107272f1bb3faa89e9a240675c9bb67e349ae0" },
                { "sc", "11c76ecd895d29dd55ae2f823031811b21884dfa11b0c400f656670c302c7843c9b5f22906dadc83c60d4351b3e44cefabdd451e5fce8d931c9eb58b8f3598d8" },
                { "sco", "28fe5d4b43e3ccc9941411a6c526784fe9dcd088dd5e6cbd263a431f129ee4a172d31a051139ea8bdd0c68b4603702cca5dcf2f4fbc0f8db7a7dc0513583532d" },
                { "si", "68889f021c7a1ee819d4552a2fdcab60cb44cd5fecfeb1567febe5a66ed544fd50ac8d380761a60cbac7a92680ef99162c52c0a0ec614b9c4753a399bcca2d46" },
                { "sk", "f86bbc1a946bb69ca7f7a0f6eae531031f38fed32f8e981dddfa5c9c5f083df28355d9311b0536e5d119cf7bfbfa93806f820bc6e6b9540432a086c8e3f37edb" },
                { "skr", "4390cbe2c480e316c2f73fc6bd74e71b9c585d8b1b08a6d8360cf1292be0e139889aa801d13b210721941aff0e3dbf6b69f622e5a2d8e6f1a8632178426a02fe" },
                { "sl", "ec8d19833706b95fe3ac4ec0c0228da0e10fce3f181c74800ab4a7022f3882860217482f3144dfe5558b0e1da45e96360c28280ed48ce93aebe5947c0c1e27be" },
                { "son", "8bf6504951bd66494d43b61ed1c98f90114f8d96ac3d038fa34edc2492f44e9738d3e16b3488d33299ef9d91b75f84b943fb1967e90b6028bfacfc15b6427c49" },
                { "sq", "ec9b620eceb7bbfe65203f64c343b3c4a1808295a33b6c42e8ac80c3e6d5b5cdfdcffe65044d756597ab16540c48a0fdfeea67e5714b5ebf303d82f6ca935408" },
                { "sr", "2f169555a132f39cadc3b5db9b97b9261e06b7dc05ebce7d392ec1cb67df1b2e0f6133365d9a0e7485df070a6ee7dd168cd8946168aa0f6077e604d5581b7931" },
                { "sv-SE", "8a83973d5458c3b46a42b1d79771cbcaa525f191da52a65dfd663e273b954442b496641da779a12c4cef36de58618de41ce8401740bf1125a37a9a27ab332ecf" },
                { "szl", "1087bf2778dc55ab95d1d8a704a4cbe71b6743dd8ccd15004a735f877eaf123eee73ed6f19a19ed37ecab6a78f9107c61739fcd4dd0563a2cce1401207c6bff0" },
                { "ta", "3548f9b9129111dac09ba4a4ef63496d5877692e722cef3e89e949b5b7e8bd896ad91aade837417958c8a7a31d0c386404d15b8e261346bcf76a5cf955a31e53" },
                { "te", "c60b89e16db458b8848ffc9f69dfdb7e4df4b88a53e7775869022a471c3b3695269d0f53e3106bfbc11b9e154f38788e548cd7da9cb9076f9f77382bd1bd63d4" },
                { "tg", "2965f1a302dc9d337c90272269f3bf6f876116beefff7674b3938f88bfd3d2040b00cfd8213fc5f373ade395756f22ec9ee3740e25949a0ba41f502aa1237cd0" },
                { "th", "53dde68e53bcac742ea189f469e66513c49b5920a91c7bc47fe4adee6bafba06845f58c195e8fedfe06b216415ed4af18b1b9230be15a5aafd2231fa459171ea" },
                { "tl", "88779a33b918c1d3420a44f2fe9588176eb0b75834a8436c74389e44d4faa48d4ccb6775d88f1c72aa7b76e3930a9b73f536135585f2b055c8ec7edf6a1c42ae" },
                { "tr", "3000f876408f188514b3e7dbe160afa4a0cb165a9042f9a09c1a827b483b6a25365f76ac96866505dc5f6139a8b573cb0ecaa553e137ad4cf2e6b5503e7ee671" },
                { "trs", "64a2e9bf84cfcbcd6d18018a8010874d0e86cdb9ee2b400ae95d8d32d8577240df18e6302bb0e24ce81e13b28b794fd2fe64296a8a0b90b434978fa507c5794e" },
                { "uk", "f92e475523c327086576c735f4298f4cd1d5102ffaa627af7d72729ac496ea6df9d2492d59459999cfbedd18cfe141b2c24c66fb26dc882f043acec6a632ce56" },
                { "ur", "7d872956b2149ef7a3d5c30b6d0e61c2c01b813d72bcd98cd48de2e4ba4b813c29be5ff398c350d7999026ce2b3b64164f2a94af8376eac00394d5dc9c58faa0" },
                { "uz", "7f58e7affeefff387d2730dbfe9f441ed2152b6291832b1d0992606f11476bd923e70d48de0f3c7ed0052fdc8d1ad867c5f71688098c80a4e9551a2f5289c181" },
                { "vi", "c2769de147437a485112b4b109d74ed9c847e32ae03bd16ad9243a103666d1af2de805c3ed201f949228843972acfcf9dab550895d4ea851079a2d9c6b42d2c6" },
                { "xh", "7ab1ef110ab3ed4de1ae9937c2995326ae880cc78d6a2852c7dfed9c50a24fdc7fdc0365c5365786efe1d3620bb2cef07c1fb7f949be678b66a83c8dfdd70cf0" },
                { "zh-CN", "a786ccca9a37d6ca93b14bc228144658eb0370ff26d7324bfd8e232f09e0e5df4ee0776d76a60bffa704bee66ca42ffb7f819a6ffe20472630dc80df0b0ff552" },
                { "zh-TW", "62fa614954ce838efde9269a5bc50b849ebd510c28d5536b2037dde294194c83b99681fecb426fb0c5b61afa55014b81286bebcc071ffd6202980a62ce8620d4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dc9d0e4317f3d5939d7348ee4b3f16f2face1f43138dda386013c9f933e6e51ec9c2156195f87ec75bd1c2d639c3621d5c3a53b276731980f84f6c703f4bff7e" },
                { "af", "2307066fab5dcbaf640222969d267cf198b0983df6fef322eca980376d3c692c4d25c844412a563f87cd15517fb4e5ed490bbf3118b98a71d864d09ac23cb60b" },
                { "an", "0186ba8127d29d6b0a1eb41fd37c3502c596f343499da8230af23d6f88d8081d5d48cf41d9c2c4f05a1f0215c5d79fd721673523b19c21526925902186d3238f" },
                { "ar", "32494ab82203a6844285a12e1a568f644b32d3e10744d33331258f5f587160c791cb70e6dd023e77cc80a3ece7c1b993cf227a7d87da20f860578dd1cae47203" },
                { "ast", "5bc6a5b78db6b3f6b2e53c4182d7365b783af0740f9496224fdd5929f6c55629cf090ee3e260540c8926e9a0f606d07ebd7eded7789e1ffcceb3d27b840f0edc" },
                { "az", "8689fa37cfb6b1ad74abe0141b373a7e9437b3f0d5f9054b60288021f827f842094bea29259c1debd9c6c4bb51808500a244ce1ca5a4a95c6ab290759279eb9d" },
                { "be", "89288e8b7e5f89e095b1760b453573ab76382bcd1f944f01c8eea1a85b81717b62ea46d15541514776fb931d8156ac87638d64664983567427dfc6d64951c470" },
                { "bg", "25b44275116877e785f7ce7b7746f9b6cdc129853ed49abe0157d5a6102e4248f42260d5dd94efdd787ddf5f3d9a65c4467329793cf1c06b6f82d4f5283c0d3c" },
                { "bn", "2c774c3f8acf570c7b5a1df33f43c6926fbd829e878660f79cc5575ef53b9f17275c75a0c2b5320204a3dfb6333789a9891e216d03636ba0a95a2ff4152ba1a3" },
                { "br", "a29c1bf9b7602751f8587f0d1182a6d78ce540e400b0d514fdeac4c1e082ae9c03615e17d6f51151ceadd535064508265a7e24ffe9fcdde187ad0016b8eda83a" },
                { "bs", "7e81b28ca05fc5dd7e2805f4933ae15488d56f89a6ed7a28f9b99c07a8fa2bea201afa17f9cc97c8e1f793f08caf8374421a13a8712eaf1262bfe6453a7eb50b" },
                { "ca", "f6ceebbd4d39dd8382ac3621c8076880399e8c8997577d83b81fc8d05681e43ec8ab21897a96a0c0dcbee67b1a5ae228c8120e11855f0530aba7df8bc4586123" },
                { "cak", "4b8affb6af763337b36e9d4ae012637fa905d231fb2e916710adba8bfc42a876874ce0f5e8e18cdfc6e07bac639b569f8afd004123d07ba4eb44d1d654419d0d" },
                { "cs", "a65062f399388ee00883eb3c59c88ccb3c96a4c31165c0f39b3326ff3ce4beae24bff6ee7849b7790684bd16c1691c2fb694ada1e69ef0db27bcbc1eef22df35" },
                { "cy", "2b70cfaa09b467a5e2ed0632673159281216d84f25e5c3906bfd28ba83713e350d3ba091c4f5ef0de2e2e8a5f338173de2ea6e3ba98f32bbb9208f4954cc20f0" },
                { "da", "0a58d720f19c1f7d40edbdaa4d68611f6c7c4a567ee5227642565eab610965ee0f7fcade779317c282b4227ab804c9a08314b817ce8a477465161ff46cbc7b3e" },
                { "de", "bef13776aeb24e2eab9e06945d4e71b3be2bae1fe52bf4dca9593dc26522d1c33c7a5598567a7b0cd618d346ebd55f4ac9ec5e4a74f96e043bd02cb3dbb9bc32" },
                { "dsb", "3a6a76e734496c000063ac02e410ba298fa4b2dfe9ec3cf37053be3c64e87af9336715b1e0e70f1f1a16bc621eb0696e0efc67124a54b55bad06cb9aab20ab79" },
                { "el", "133add0063d577eef7a940f3e9041c0bc806309eb2daae09e6e3d513d5386340c674ccb8e4738c120eb6f2f27380320c72239d376f6bbbc613a5656437cf2c72" },
                { "en-CA", "ab565d6d1ed8d403a02c8426c8f2bc103f5900ad22a741e69489e0dbe1aa9b182e3ad46577b26a47572a0379dc44b9e3ce89f5cd05a0cf0b5084f48f75d48ee4" },
                { "en-GB", "0da73007d55c45912d88912fb537e6efe9d93f82bb158946280b939b4b676c740bc75e7abec682da271431a103e273bcfb39a3f77de23b47655b3818e086b81b" },
                { "en-US", "4512672056a0f713a1c4563be07ac8767f0320d9aae049dc7b96cb481cbea050262b8120c0314493702686633f7bd4a9c6b4656e7a99552d7a7819543d148dbd" },
                { "eo", "db9a863eb874303a2f45edf2fa53512d12b654f3ca214b94a047ee00ff0778e99a3537872de2ee16d85008f1b7e8b45678028c86bb766e460c10efc0043019e9" },
                { "es-AR", "8f1fd8e075cddfb1d92ba8b8a67a00b7ba16bc46904adb1fe7f249f182bd7f748ee959515d0907e8f097a45feafdbc94e250068ec09c9941aad524f34a89e6cd" },
                { "es-CL", "bc20dbca8aaef40e6b86cace5a1b77338e22b37f970932c28e7d79e9d7b6623109545c7095547bc60105b988adebea29dc4519dcd8b03a4f8bdc1bb00ad042da" },
                { "es-ES", "a26301798a424ce350d5fc5e623e3e9c3e3e8d75cf83384c79dd826b7205af13ffa4fb69c7083a8c6652291a9b15fa0bee92aa64a7bd3164604a7808b71a5658" },
                { "es-MX", "51e78e7b34f0573fd10d05669ad22670f248ade86e55b8f5eb7a1c4c9f003f3add9993b609e070cdb13dadf9d6cb0be13d343b9fe908398e7e864e5c76d86d61" },
                { "et", "537ae197564de8ea0e80e5cca8d8ce232ff2e72252a7d76346ee470140d4e04bd9856a5a6106f97652da2d581d2307c2a0d881910a6e661665f8e2bb9eda2598" },
                { "eu", "ef7ed04f45e187b7f103832b36a28e1e8c59f3a89944d680f867c2005e41242fa7dfe18ddd61f13b9cdc5c9818874208c83de9c4f23da4bcfd1ae59a4b050154" },
                { "fa", "e159d6716cfd83c467c647e27d6f2f10eca7d4466d7130bfd08c224594d227dc5ef6beb0bb65f70ee5cfcffad0ac968e349f029b7de1ddc35526a276041e3773" },
                { "ff", "45286fd4fdfc0d96d93bc0bdd6d6d86d38ec747a848b181ea6c4d3c5b7e331938b8c9dacd633070083de7972cab08430c45a6267cf453f2d05591f87b427725b" },
                { "fi", "e3ce6a6a8f12e1b4a878b2dfdcf2fd6862a195d1326509161782ec5f0742c496ee92a9419e24479b450bece64fc4675c60fef2b1abc73d4245e5f0ae605cf1cb" },
                { "fr", "18ad6aa2a9d058827dfe3e64a88e9288ba7257629b929ce2a1474885c181389799bccf25dc40fade98ad23804ec721046d31ea5380f4627ebca36dda4066989e" },
                { "fur", "68ac0fefad26786bf15e6a1666bea03c8b02d5b21a76ae151aa6ad7381eb5ad05df44d32a9eb12f57883892441daca1b7808359d3dca394c0013ac8d658c163e" },
                { "fy-NL", "182cca8917fa424ed31d2c787480fdf876682baa23f2e37d651381b6a896cd4b242f0bdce7b290bdc07b4656d711a008bf32da8fd7112dfb82e8fec2d92ea8f9" },
                { "ga-IE", "f2f91bedc78a1a9b4348277aa53088fe2b1ce1ee95dd9cc7d3fafff0db88fbbb6a5ae817ae86cabe9dc15c3c7b13b572734d4af1b6f90fa3effba96c1eaf0bda" },
                { "gd", "03607a14f3fdf796c9d1b7a4fd3d1e0b50258bea7dcd0801115cab2475e9c3d832e3a662bd173c16cf291699580e7f43b833c2f294b6b5c341d4909d89f36d20" },
                { "gl", "ce89f4867d25c8a66ab9053e99bbf6d8bef7a642b7f85e613b9349b94514e5a5477db9977103053af41f462ae34df4d3a3a2f574949ae47cd19f6d95900572e6" },
                { "gn", "312126d41cb1d04ff773a022f31bf02846cbfcc5032c82976047493042347332693cc7bf6bdd910cefe98684ccd5c65751c877b61fa80d0ee8aff31be98bbb2b" },
                { "gu-IN", "f4f7f1aacbfc6d1b5aec014550fc5e87679e93abd325f46a79c78eda28bbf8b36a3d802979d3cf9ded3c7d2c77bec2c4daeefde69163deccbea44790ff9ab6c4" },
                { "he", "7ad7c8c0bfd31993c799c5c58def1862f87dc38213ee257e3a8a0edcd9081d08657dff7027b6691af04d993f29976897326405bc1208a9382a0f6f2940c5f610" },
                { "hi-IN", "f68bb551d82fac02febdfc7d9eed44fca537452fb09736898e497731ce99ec6450b4d0be19e687622415abef968eab68b1c0ab141fd0b2dfb7fc0a2a243c8cb7" },
                { "hr", "77fdbc1ba0a1d591fcdb8749b902dcbbfb53b816f8ae03148c002c3e7f707ce81b6b240a0169ae9a8640fe34e2858e16099a6e6cbe2717feb052ed6fcb50cf5a" },
                { "hsb", "4005dfaf31f3000d4684b0af04c8083037ca73e14e8e6c08907987845bc169c38555d471c4e9e22f089e92eafc648c2888a4ef366c2e0d4bff4e73b9cf0c0c25" },
                { "hu", "79cf323ef7333b8279d01fc94492bcd584135bbab4b0a92c848b659dbae526e7fed631e2a243fba586f85f23e7a825f947f3f38036608296f96b2034cab33411" },
                { "hy-AM", "f8f4697322f568ee3d491be1c0c6e8153634632420c287cd6df9431e080eaac655af9a95d7ea236ec25ace7ab1b3aca247d7ef96f9f2ab415a43863e526632c2" },
                { "ia", "3c98540e5690279ed6a43f0cbd3f4a7b20f44ff11666b86a72fc6659b34bd479cb966563bfbf4c65dbd16aa2d883a90d7f60721b0b9e267b3b8421ec274dd878" },
                { "id", "34c7923d8d6b92243fad73fb3ea172bfe9d9c081ab42501289c7cc9cc249ce4dd55ab9c6624ad8a80055113995ccb25e3d37878e9ebb69ce93b6364de87184ef" },
                { "is", "c0a4ba1bef99bd2380939b838431c4bf240cdbf7609c3f9b1707d41d3233436cfed72c7e45b43fe830c335b87af31ec2dc14a5b2f9c9ac0aa1bcee9099d77dc2" },
                { "it", "f3b6fdf8f8df2533cda29d525cde8fcd7863502da782bac26921720116e3b12bc354653f6a1489d75021a759a54b38326edeeb9a2530f21ebb20bf920dedcbbd" },
                { "ja", "110a2c06b444eb3bea8fb29a1e58a12c44f9d8c524fafe04109255b765390de4bbe9ce5af8a975621bb4a318fcec002927b615382a948445517c7b7353d72e57" },
                { "ka", "6cf5331b71ac42d4a9962997727364cd1161114451a6086af806b988dded5099df871b85fac8953adf9bc2eca9d0c9179162c34f521f786075fbedec36f1395e" },
                { "kab", "378185f6520b55b274df2a087a4011cdbe5744751af6e5ff1b25651b26fb8d1bbd148e00e35db1e7e6d04f9bc80ae49c0dd54a959bcd28e26446f44637397c3e" },
                { "kk", "4a94df86506040c656db54b4936c1c8902915e511eda9a59564c6570f1918ddf8dd8baa30b5df75876a66ca70b1bd1c9c740c86bd9af22db3fda180bd696ee03" },
                { "km", "c764b07fe19bc707be89600b525f3637632e36044eb5264646060683642209f29f8b0ff5a0bdc820b82645c45a97ff91f103ff275b3cfc993d9950846eab287b" },
                { "kn", "bff970f6a4c9d1adf997bd5c8e16cfaefc712a652c18f4657cc7fcb7cd95ceb2fad9beb04bf0d6c010c7cde34f2a3cc761d93ed6d5925cf95d64f797caf3c7d5" },
                { "ko", "cf3d4c8102ad7ffd8d22ae6719019900d5b772c1c99fd7dcaeb421453be2e4c8cf599df830ebff50d9c347434b23290ce7019d6abae766d78001f028a1420402" },
                { "lij", "abb4970feffaf0df066ddcccae7d0db2cd11a6cb3201375efce523aa37774abb86d570ffa27152a11d9dffec277f049a2258ac0d294296cdf6c192f2716d90de" },
                { "lt", "8bc56812e739405c338f990cce5c684b2cacbcd7c478f78b13e47aac620c57ff63c28e41941618336ef2d5fe9284c63e97082541335e254393bc67b4da572e12" },
                { "lv", "5e51d9005615669a97ec8e1b00398d6cedae5acff3d562b9a671d7fe6729f464c41558148d1f30bd47197f6fab7976d51e5621f0bba105ad0822381211915a0e" },
                { "mk", "741fad3d3bd7d28a1021892ffee90c5305954f6f7f1b924ef9c12adda4829ebb9ce5eafb3a90de8d631723fb889dd4a4d31c32c776ed1f59ad4b7316038bc4e1" },
                { "mr", "3a5602dfbeb681b9cda0d55d89d77cf551611d9461a32715dbe15d00ba5aa9551454cb04cc0e29aa23dbf4fed287a365e7af7d27c0dd77e03774283a622d0d77" },
                { "ms", "3665d3637fff28d98df62775585ba023035ce40228170a2cd58a844fa9908dfde62800d86e35eefef1409f650b4655bc726d1c80bac4ddf9e6cf9abac6808ac2" },
                { "my", "adbbce1a8b9cde548211131bae8285c956af88301e9b50db80ce31219d58081e1836f5d544640eb3b465e97a628e603e14ac338af1ac1a7a1a4a2aca20098188" },
                { "nb-NO", "5ff5eb469ae74f940985058352b09d23fbfaef7143f4bffc6a6ec55e093e721438f9786791e11e54a20e290cc666d48fddecff6694bea90343d940aaff6d13ea" },
                { "ne-NP", "edd6399291ddc8f92f756a9500a3863c156eb969b96bf1f1c5cc7506ce921be151a3bc78e03640a0fe0a1e31917040ca0db23013acb372a795ac6ddfd31fd925" },
                { "nl", "f65435328f880cc50c7907dc85bc0cb73f0383b1a7ca26cd8b22ac2d109bc4d561173e8bbb8a64fc150a4017163383c8ae033971ea55fae531fe6193044a817f" },
                { "nn-NO", "476e7505504a9d0a3f698f9ba20c37374b7b530c053b5e7c4be163eac5f2af802eff364b0e90db8db10e7059776ba75e0bd6037a84bcd56534582cbae8c0ea5b" },
                { "oc", "4f9ada342bd2fe5074c28aaf6325f81574881cb13d87c5214f170e3e5f471bf0e8a30b231152ca901eeaff740bcb202c545f4213731870d5f3e119d061bc21ea" },
                { "pa-IN", "0825e3516aa7966d45e1938080d72bae0f0dc3d9fb4677bda2dfd7184d957fe7835825135f8ee9d89743e5cf99f8cbffdd7ebca44427f62d805ce0821b39008a" },
                { "pl", "eb03a6f371f4482e7e4fc83ac689d2b28bf66a36b9811da32ae1534e7bf089e628c6725b3c7f03825e153c1f747a3264e71b91355177e681de8996ed89a0c27c" },
                { "pt-BR", "e569b7165d08b46ff9a93d54c9b404c30fe8ee269a2add3b28f7db9fde144d2febeb79b73c14b78adf44a550350a9d7af709e6a551198a4a7943135530553578" },
                { "pt-PT", "1b7efe1f2c2a51ebc125de9c3e6c9b758038ba8050239dadc5d137cb77dc02c01b936cbaba4429dd95f459c27c67a0f0d4ab8a997bf023991788e2ba86f6e040" },
                { "rm", "a7e0cefc03e6ab35095f1e342e971188d202731c41f6c31ae1a7a0478e14e926805a9d1769e6490cdf3b61afd5e323a04d625304a81be4692381975a9a902f9f" },
                { "ro", "a292c65032bdfccf885e15309323924ef65607c6c87fde87227a6032ebab88e110f62615a49db26f559f39cee55e3cb9ee162769d07323dab1a9e08e732be3e6" },
                { "ru", "ea2b25082eb9e8ec70e8e233551d01071c9c0a8e9491eaad89e2abefbec8d6d1aff1b1619bf6e92103754fac1f4bd111e7cd241d2b54d8bd2938d9b31d4e417f" },
                { "sat", "4edb1078317e8c861975767b6364322326a2a6d386dd18721793d6252cd77ab4332314c3a75f3c408cc52e1a833a5520089b422125d9a342a1dc00f6b43fb46f" },
                { "sc", "b277d48db1111f4276a5cbcd97645b788c7e14bd1a196b1cc4439ecb22d31ac86757ce1bb1a174d72449c94ab26ecf313924fe0a6f44267c77f3605b16df1eb0" },
                { "sco", "c96dd6e6347ad733aa36109fd14ed991204f61c1641a455aa3800abc894915ba2ad6d41d257c4c2390bca8bff9140752403232ed4f8f0ac5087e899f548d22ce" },
                { "si", "321abc9fbba775e31ce390776abee272f6b743baa61532f0e76dfe3a8a781783784d3113d091c98681f38b2133d52f4421669c53b90a2a413078ea993f145e24" },
                { "sk", "c254f8f1e27b64678bd9afb01612724f5798813152c9ed9a208486055e0b541209eac124f128eca802bd9a163fed7d571d8775f548548922d2d3c93d580adfd1" },
                { "skr", "e373c100b6f1350d52975bb8e0bd60f205a7d0d63859740737f6d2ca47a626470fb4dfcbdf43d8684de0483caa609734b05986ef1014c06d0f5cbb541fd9e5a8" },
                { "sl", "4a6302d72e5a0cc6a0c4eedb8225945888f3141fc6255e92b05830b720c9c22025110ffd6c56274f62361705ca6656be7ebd1bbfdb3a00b540c2e02d13668f30" },
                { "son", "c7a63f30efa0abe5c96eeed39104dcfaeb03481b8887385882956f9ac5ec1c82e3d31c34715a9c072675a9ea46a451e78f61aac11670e527730f3cfc21baaa6d" },
                { "sq", "5694df3fe5f4fded48ae5fe397c44179e98e722acc375a00d7cfc61ecdc4a0d2906e676616c8e8f58eeda8645423f42c4fde0083c6f9d360658b24273a574793" },
                { "sr", "c6722f4e5ae15c6a9c5812d59fb0a6f20550d744bbe66de26f1f8fc7dcc0fc7cd34ef365d96e7cbc92d9ccfb36a7515cefbd2915d39f7d662f19eee13e8e7d83" },
                { "sv-SE", "246e4ad7c466b37d9cb5531c34c9832f60f21b961bd3e7670288b5fa4b613837fd5cd71fa10d3ea9bcca5cb5f8863ca4915fdb59124c602ae16964eb0c0f9f4e" },
                { "szl", "074f5e9f89d5035db347c150d4233a62fc611900f702afdb2eb5eb6c893227f707745c417ea39df2f29b52adecb731fd0b3202173e79369146a36b8213baa8a7" },
                { "ta", "1f09208a4156aaf928384d034b59039ebd1f77fab211e1333361da3c7b47b696020c8dda1bbb1a6bb97c660e093562f34b119d9437164796c3708703a6a5b5f8" },
                { "te", "664abfc08243d35b587935278f95383c34069dca18d769bf4cc2849297c8871d7a5317044fb8300316401234c5cb6f15ec3509aab14136991c370054769d2846" },
                { "tg", "b17afbeda5e95a9261d325f512c2a3edf8b6953154448dd133250c9ad55a9667522a64568827917aaebb51f8d56de9438c5aa23396fec12b0ef22b408001846a" },
                { "th", "1d3b8f6a3440c8b298ba88d292a4d26650d7626439bd6fd76caf2928fd932f140d0ab9587bd07bafd76269b61f31057198e202200ca280ccd5f8cc877dc78cc1" },
                { "tl", "5d97ce8f7eb79b9440f635e6eb02ccd3bd3e8e053411e0f687e18941f136d3b89b3466950e07dab99c86e85b21fc929f6b5de88f0630500a92f8f33592898e5d" },
                { "tr", "f8723a3e3ea842654a1b691925e4b414e549349644f01941691f7dee4f8721bab24d41fa0874863265c62d14c1a97fdd67d363ec4f5be89ef5bcc96cf1d472cb" },
                { "trs", "123a1b08b390bc32f5e09f0fbd5c46e216e5618d55585f92d1c434ca0e5e3132ce961e7a56f4755f13b0011acbc066bfed5521e001c3b9142cc63f26fbf4344d" },
                { "uk", "5a1030e1e1a108f487f293886de574be021aa3e529866bc6545693aa0a8ad5c900ccc7ccca19ccdb6dc03d5a2daaeda77220829a34db31e17bf592abe38b6e46" },
                { "ur", "63696946305993f9eaf36a59fd7665e84d54b058d1cdd9317806199bb9a51b7f22949d24fde654f0f32de723528ea6347a46e87b90fb8fa66bd8df126f2c58ae" },
                { "uz", "745a3e82aea8d3c53df14de4d024407195bceb578bd0fbc08b75af271256f8dc9d85fcc0660d4752f0dc604db9ba0ddfc4cab7c9582fb61656a3e7888c916803" },
                { "vi", "32190fc77df9d9062dfcca4d2f142ba232f3fd844cc8169ac8062288408400008501923dbb14d7667ad66a4aa1a974b44a8dde1a2246f418c039f61330b3c6f4" },
                { "xh", "6dbef5bb79d6e74d3be80c6f09c5b9b943cfaf439f56c10b6c73b05898ad4f1c0f1d656f9a0c663e6e842956eece85be853fc018a552551c32fadf60bf26e833" },
                { "zh-CN", "059b913d6b7574a50bf017a82d5576690477dba61a615d6160a6ba447a338377610e264b1b467cca2cc66c103c3ff5c08c56f1289e4031610a942a6d6141d069" },
                { "zh-TW", "1d9ec96120f8b9e57401a7ebaaa55d9d91edf7a0ebddaf0a04ec264ce313456a210e6c534910b7b2fc86421b68ed08785f3c5fb8a86619702edf06ebab166422" }
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
