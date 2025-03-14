/*
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
        private const string currentVersion = "137.0b6";


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
            // https://ftp.mozilla.org/pub/devedition/releases/137.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "10bc64ce1586ea6c003d26f172512af58f4d4df8d1165c8e5d0255b708492a5dcac0ed0584a11580759c3783adf7f7a81fbfbe97ddeed6a7b59bdb47869f5663" },
                { "af", "edf8eafd94024d2f28ae9516f6dbab9215aa87a51aa9bef0845b7f1cd99e462a2ffe588f127f572c9b97de8594d215228df313d3cab420ba9e2ad8beee4781e6" },
                { "an", "8097236b29a91a3c3244da205d1b724d929ecfab87a30e48740e25fb7b332fe2f0e4bbf272410f9ad49e316ca8e28125f1537245daeaf47f97c1db3f9de37387" },
                { "ar", "70f1b3f9201886a51bf4e121f0d2b0bff2342bba44523e4a5bea9e9180bfad6c8a6013360b274d87bb7f0ba109cb19ae7d1ed082ec7d701130680e757cb7b49f" },
                { "ast", "5de7ed3ee9f507bbeea0052d54e9c43ce6fd2febf7159ff4d8e30e7f55d5fdd68a0cd034e2a3f73fc91c5c82d3367196521d1a072c6045775e4b39b24e56cffe" },
                { "az", "21c3b24024be5fc4f76032e6729571dd550145affc8cd28e105cb0b905f58d6bc04d8e174c4265b411ebc06de9a4672fa313e02d5aff85ef629597b415cb56c7" },
                { "be", "6550bf7c24e6fc935f2f9d8796e1234c4dd7699d4bf0561e519f94815013bbe602561d08b24836e9c196bf972dc4d981ca70559691b12b246daa8183a4fabf5e" },
                { "bg", "56a0436a16f601fec8b53ef39e4fcd44b6991f5ebf79ee198ea30e3add27696eb7a5b3ad7b312fdf964a9db790b96332e57e7bfd0b8d50675004d85cd57eff65" },
                { "bn", "7f82077117262f5614da6d9e0f46cd080c810a966a3f5450d6a60cfcf28e6b7da8d381a0e958d8891351d648d4169fd56188f9283fbc048b95de6bd79f593322" },
                { "br", "42856cc8820d1ed3afa05e8a8e1108e5dd8abb753c06846e05e75d6b1690dd01952531d3d3d07a0a63a4d5611b574fce58ca01f3377fdb7732e8a764ceb5dba3" },
                { "bs", "5b3f32319a1f80ec3b6b51035a7debf3ea2fbc602f4804f0095e6961780ebd00b926a39b255e072e9a5bb9ab65ff4b4b0400a717e257111c21ad051d9d9e0a24" },
                { "ca", "339857d1b9d0f2a546333d2c412ae79075ff97976b7106d10920c8011b142fac35dff2ab9db766e835b765b9d51b32340e8570370c77e88c80ec78573fede2c4" },
                { "cak", "40858d4fb63d76831b2889aa2ae735289b077a3c261fd5609edc338a32ad9d1049d5dbcaafc04f846793ff9c01ae82c34c5bfdd19df1ef545fca34137bdbf608" },
                { "cs", "ebaa8d90a1504cbc7367f24bf94b3dc238ae99e670b1d52ae9eebdf2f62e1d64befffda73196ecf5fecf8656f89be5c71f572b5e080def14aafe8aca0bb7177e" },
                { "cy", "6211c30d07cd04d999084d721f7b4b91c60d9acdfdd8b3d47d66769819999361e11ce2648a554ee18e7cbf0607316755d180b13cc8d20c62627a98b6620eaf44" },
                { "da", "7b0321634db81a5b2ba4686c4e78a47e40074ddea5cc2557c10c4b3b4a97f2430341e3fe8779506f7c350ccdba52a541b4c67b148ef6ede208aaa3aa58cfa30a" },
                { "de", "b9ba686224ecd6c1a79d5ff1c5f8b46f306832f76175cdb76ca22a86a182486571de33e90b23a74d0b1943d8d89131a5aeb77bdeabd48151c89a0f3176ad8d54" },
                { "dsb", "2746dcc20d5d60aaa74bfd7d2b25f21025a1487c89409c23ad5ae1bb8db2346cc83a93620c6af9e0c86c96125c73295363ef0800379ca1315b2394fe5be07405" },
                { "el", "a246c5ad4ae31d264fe54f4c5b9bb9144312822dec03155d5b98ffd993fa9fef84f53f068590a3e766e15fd37f64abf2d63d87d262dc96d5fcf4146fc9233e20" },
                { "en-CA", "4d3187262de4581bbfc70b7a742f0449c74cf0d713af92d2ab94b9ed98ca4f4c8cc5c4a664863f014391ecf7f2517fd99f9f4001bd7d4a34b3983a72b38b791d" },
                { "en-GB", "dcee31b50c247acf5966d0a7486b1d117d1ef8388c73e22b702b4c05daccbf2ca50252e4efc13ee5f19450597b573d66856e104e9f1cba7f2a27097f2ae9850b" },
                { "en-US", "29830109db55a2bd465670bb91824de89fce4d6945c254dfff57ec301f4c9f74e8966311611ad67414ae6407c3fcefccb31f6e11897d5c9c9a25fc47fe6b7a24" },
                { "eo", "1761bf05b6b6d940b489093bc973e3d4dfce0d2288c3a0bfbc38306297103a9ed1baa6b424df6d673bbf35a676097f46d4a3afe34247596c660daf2f016f6a95" },
                { "es-AR", "2ffcfcb9e4c4d5d4f138e6e49bff47630b858291f6eb3edf3fe2be3f131dc343c25ab4121360ad80d2b97cd29daa9482752b3e20050d0a880981095ee6595b68" },
                { "es-CL", "f609c8c62164ddffb628f4a7d9f7a9e03ede5d655e4972993adbaeab141951fd13a5bf9f2e447f855e11c6a1e28f796e5c435f63b3c25951234ae30a48942e4f" },
                { "es-ES", "997c18cefd8ad68dc3d52aac6d14ecec25b048d97175f5af492cdecdf4a5c99d2663e7758664a227b64ca17c70492c3720e4546e0bb94415e7cf46e88de651ca" },
                { "es-MX", "8327205e7803d15a9f5339754bb5a314648cbecc30a33319caec835170edafde3627e1a2bd93ebc05fc2e1cde2d57c7af21ab1f4b2713faeb963866e1ebc027d" },
                { "et", "8457ea430d4887965a96f94b709bca1e43bae4f3f112baa9240ecaac897fe1957ef58fc324da3c4e85fc381becf30264d7713b79c5b1b6bb8ffffb1a3a152d15" },
                { "eu", "a09745b0d5e679b440ffc8e1b81cb0de5f7cfeeef7f3cdf6efa639c940e1765561e12715fec19ca568da0958473d14ef1a3bd78a3e1a9fc2cd7858560e21ea0f" },
                { "fa", "393a4ff0941ddba0372828be6bd0541e9d0c2becf34116259001d9882e87d160ab1fca151cc37ce66b0aa337feca815747e3e5bc45157932ebdb4676ff3e0cb1" },
                { "ff", "f0c4f0f2f51e38136929d26a1847caa54610342f1b03a53ad0b8914a3eb72181eea896effddc43b183872ae704f7eb29cd1b729cca8ba85bd5dc25edafb47cad" },
                { "fi", "683d52e8308b3961bf7a04883316f5723de675143389a59541266e049ae9f337ebbaa9b0ba274108bdca402adce0837cc3cc45aa2eca4d0a075ef95f4348d6c6" },
                { "fr", "02ead23e2e230a0513ff3f54fb6901584543681959587af28beb85b64f0a309c80b5af64f991c60600d3b8d2fc17a9b07c0c2697258506cb602215c91648e9d7" },
                { "fur", "a2860a0613fd5190366846057faf5a501cfc914aedf63731218e8cada051a8097627aea623ce704d19a823dbbc25e927e65240e92f5445f251d8ee107bf5dcd3" },
                { "fy-NL", "6ffa247d454d0c509f48814a838d9474201e1be84de113da6745d18f8eb5be90bc5262ec55959ed723b2ebfc67e6fa050bac646f4733c7b3e4487c25c7a9c66e" },
                { "ga-IE", "382150995988fc970ea1fc5cbb132194d11a67bda37980c5ae58d2d3d5df6f46dc957c4dc63171b3a31a7947224e2bce48811ce40555a95b1a4b3dc98068eaa2" },
                { "gd", "b6a77696aab9dfa2512de50cd709a675a0b559b6bb273081597438133cb20bb01a4fe18617d4d8f038a9b717bc3f7c2817c7dc8cff4a8854f0b82a57f904c10a" },
                { "gl", "a08cb5d3a100043c3a75f23b96a9e4dcc68103659bb45515318472ea639872edbd46785015f3d7635779c87717978149d238e3ba3c8bf1938f234e6e27f980f8" },
                { "gn", "8733ebc0acfb40ffca2e45da55c3eb67f9b4aa96ae593d2092dfa2cdeae3b68cf4b42cc38b2843dbb6d8c84c257d849a5eb1158cf1f90c73fabaf07c36d1ec51" },
                { "gu-IN", "cea85e2c487a50378d5f10e2b15d4e8cf8744ca5ed9a71bd3db699f1aae9e1767aacf8dc4403a74abd9b4f65e6706c74e5783334750f6466fb86a9183456017a" },
                { "he", "3628b087cee70bc94aadb2156b41f0cc8348baed3c24bbefe17317f61b930e10a444470a244ed61f9ce9a798260da4d22ad4bd3b8a1b6d52d66df082d8e9cba7" },
                { "hi-IN", "0ecad33cc82b0b5bf6cc6ef77a78403c5018e4757e98642ba6cd36d3bd5a11fa619d2490e33eccca3a076d692b06ce9dca53900b9ddebdb9c531aaf265c60381" },
                { "hr", "e62368b863d1b716facd220e8d9baa15dce90ade013824fde33116f50927819abcee49d587683b3c7079d88201228535a9be395e538ee444b6f28da6f8d94c4e" },
                { "hsb", "2cb919f7a8dd0c8a0e6b92348f7458474e8c80d9cb5fe3b75d8ef4d771448ff13a78d9b4218d18600f5c6c5e72fde66bd7e8d9d54e5d7e3abb06cfcec186f9f7" },
                { "hu", "1d528534190029ec7219120cc675ce1bc8a8e1ba81edc632ff9282def0d3518055133eba9b4120b6d31b959c9edb0d772a7385a840705aabfb72b76edc70bf93" },
                { "hy-AM", "80e94675c1a41e74d7d972c4d99dc636527f7739fd945f58c79fa680e8c30354fa0250f9b4cb9cccf2984a4171c4624fca50fcf2db447fbc5ecfb5157013ddcd" },
                { "ia", "baca2a5dfbef1818dfab9673f3d211b3c011bb304f39e12d875bdb29bb585143d3e1bb586ef88deca555c47cdbac552eafbcf4ef0c727b05f6b7f11fd8b6feae" },
                { "id", "00a8ef91292210518abecc99f29d0ea5d772c7847be841e6f8e87ef0eebd727de971aab302e5c441f19fc454500fa00faf0a88753b2987677a93b0d32b2ebcc0" },
                { "is", "3e30dd2fc12b179389afec4fa86044d8d2ba3fbafe8e7caa44dcddbf050a2fa9dfcdc7196d743116ad74e69b91e8a8cf5e01672717b5c2afaf0834e9bf82413f" },
                { "it", "cbbaa2b80a9f04b6c79bfd5bf967f1988f3ac9fef75dd08d7f88893b525082bde8061e778927160b9a4628dbc20e71d9a73f5a2f51a94ba6861bfa17953f0fbb" },
                { "ja", "3993d69ae747016366b8f003b0a9b59b06612fdd78dbc9320375744528108d35df47974cf9e1bcc4134b28d909290db06c33a1049eabfc6e30bfb725e4bc64a9" },
                { "ka", "0d7a79ce749420f3bd77c741f35a38a963742216671bb6eb2af0718a3b7dcaf254cbd2ea16ab63aa1a2c79d2907f863bc97d3fe258e55361e06d694a4a8f0970" },
                { "kab", "8a47b5784ec9794498f7b11db507dd1303996e2c4b64109eaaadd12b7467d980819a063363667b3ffbf5d2dde0bf1d0e5fb301831a3462ae65090813aa0f498c" },
                { "kk", "2490dc1f3ad21195a809698696fa9cd053d86c473c6224c8ba4a19b6174d67a41ef1291ce50add4dd69617b00d98f75161e9a464275353cb42b3b473d42e89f8" },
                { "km", "bddb593972c97b30cc7f50f5dcdcac8b2f77b99f6063eb2a3ad99b31792de1fc3804a146b27bb9ecda521d8044d96dd8dec34fb6ed82f3f201d6dc1e95933426" },
                { "kn", "5c13d332c3a92eded3b1e2606e3a32477c298befc13942f91c012491b099d3573e022ab23d316079e3c46b0d24e37f7566adabb8a8d3373bf5d2a6875ea272be" },
                { "ko", "a955cceca1acfcee0e6bb949ae40e2974b45e26aae7ff5505380fd94dfb06400f1d84d42cc0b28b97858897f7021caa9e8bbe1bd1cb4bb9c5471bd410c03f330" },
                { "lij", "5683fe91ac9df8a9ae56c0db3298d9c2d52ee23f71ee809c74a22a605a00eec3102431656a92f86ca015845138c90d6dbbeaf8e3d2125bde33560000fd092ad4" },
                { "lt", "298949d516eb015a27f92d6766a29c0f6434d35024858b00444b128c28379660c2bbfd02bd31402ac170e4845a040d341ca0dd3e339cedf19269103284af9f0b" },
                { "lv", "e3dc19368669f7de21feec593ca720e595c1c53b2817a989f614a79647ede90cad197f9f11be65441f0af86f476a5498ef39e9015e67bb9200af027937784a90" },
                { "mk", "579596774de6767ece16de26ee47f4b0114ff075d7fc985be9ed03cdf3ae433f0798b6ec22b9b6236771aadc190f0f9c9ee0f5e622a8867635d1a6c002ca6a24" },
                { "mr", "0e9e3183390914fea8ed304d81f1d1edf36a77822ecc537db5c5762f852419a86aeba120162e169e5f20c0235694a567e40279303a38f80ec11c9d10d47de421" },
                { "ms", "f519299ce078a61d85a1d30896b4a0b8dd02f035eed9ade0d4f7b80aa3937f6eda5e2f4f913a127f3cfcd82c80356b2f55a488fe63fe2cd7254f514f262a2bbb" },
                { "my", "2fb98ba2808d70e4444dd94e14761fd42d4602702bd4f6188b01e0583bd3206845c1c95b98a108ba5f262d247095a626090e061af256199ea30f5ac8a6871f46" },
                { "nb-NO", "a1a252fb29227faef1551c7664fc0cc05b5ba4b237e70ea69d5b12f6f3313385badc5b525164d4c0851269e0b970f266997a94550d1c8638aceecc3c5a5daf0f" },
                { "ne-NP", "4088816a9c4617857cd24956d52305d245dc722f1168a806021621dc0d55a00310f8dc75b5c4ddc10e3b7602f4c0c284673e305624919b965dffd5c3e0b9e08c" },
                { "nl", "f168b5ad5313174db70fb380d8e169c332122a5cf8f189f87295579553d9e9ba4b556b81ace931cb2260c8ab9905b5e6034caae5e81d2c62806b2784adea0b7a" },
                { "nn-NO", "cd948d8dc3c76155993824edf53ae9f2ebbde12aff18d3485f92fc5b61266e034e0ceb9f6f03d1c58ab309a61fee6baa19adf510efe69c5cad53ff84bd971dba" },
                { "oc", "ff50d5f6fe0153cc8e1fc1f9b012fbb6141fa4d9ee9ff0ee7a3559546e7cfab3f413212fb5fc6e13fd3ab89cf5909f8604ad6426d4eed2d5442cee1dfef80d4b" },
                { "pa-IN", "e167dd4e40d793edae011e852fb62f269a63a8d93e44d262864bfafadeee57693afaa7fb1c6f44789355630afd435b7a281a33ac96fcb2a11c7bd7ef7af12083" },
                { "pl", "592c10ffe5a97f1f0ef2e51a93f7a80ee4e3da61766ad955f3c7d90e7098f0cd66ed9844bb57ff857bc90e143ad8c3018b0da53fde19f4ce8bced49f949cf587" },
                { "pt-BR", "b2fdbb806c6e9ade85f105cef6ceb618d81328d23ace3721cf26ea4088ac6f84da90b7d2b72205f2cd96b3f5bc06d9dcb4d0a12da15c2d11e4f3713b8606b922" },
                { "pt-PT", "d572358bebfcc8150f58e7f4cfd8c452be22397b66c77076dc3bcc4cd202470de2e3e9b302010fb1b806f5b54fe40978ca99e5ade8ee9544143ea4c43b059945" },
                { "rm", "a00cd528c3a352a6d84e7feb874e3a35cb116eef442d1605fe7fc543eb77c63b3bd1fd754503ac7ef160b81c441fa132e19fd7694fbdf804cc3a9af12c1995c9" },
                { "ro", "321fcfde6c1558612650fca3ff48dcbb6e7fce79e80154c2f680ccf5720811120d50c80eb0e5e4d5bb8d8d1ef9844841a84b3ed8f02a02fc86df2e79ef88d8a2" },
                { "ru", "1c0e834d07092489fdb59f0f794181e2a1b81841d74a9055e014585489c695383ef585c6e703e0001ac64c2d13662261159602b4c24e37c87e471f8ff3f94856" },
                { "sat", "246358597b6df55d487cee4320e68b4c449cb91cdd2a9d099479186da7f25f174c572996a95bca118de1c908379c39a9e300db36dfbcbfdcdce90a084234302e" },
                { "sc", "c786b6b2de02d19b3c2ee1de42cef40b716274b21852f6d4ca9a769978807fa293fb417ad9c15be9696933e8d0c28ebc122cab2f65a95f319a5ca8bdbe839bcd" },
                { "sco", "81d8ca319d20780a14d091a05d47ff709f4c3e0757a12d3f57a61cd8e78fb97b1eb3faa64933311caeca02faaa8418c2fc9b777c58ac3bd06df46a9d3a3fd295" },
                { "si", "6e9f7f3e32c72f6c774812ce1ade25ecf7a2bfde6241fa53067609c119562d7d322f98a772178da15c911b7fb912679c7a0c1bc2793e539215333b9811e265b1" },
                { "sk", "8200be605aeaee7c0a0b08b7af7fb96e9131187fa4c405f70291ede418d5695d05fa9ca512b80ee13d892815a26a6456d5b47a6a893fb11ef795c7d779e4ac86" },
                { "skr", "5742a575fef78ad9c1a9ef88cd0ac7cc6e02501c34bbbbfd3371c8a9cc87959602b17a687a10b95b08116855e346913712539509b10d73c4f83af4f01f2a8512" },
                { "sl", "3f4b609cc2c927268e544a474e7aa4f23ad5cfdc03408a8e672e51fe9921a2c6e2a479c47a06caf46848bf9673054a1df166d29ce699d89e158f0e16ca186227" },
                { "son", "0cf6557d5275345c9e2e94794ad37056e3d530e1cfe8d7434cd02c9ae24c560bec54f1169f9aec51e875ae5b51c5bac1889512fd22ce99290a19169ec4a4d58d" },
                { "sq", "d16e7f26fc6ab39fa8d4c92a95bbbbfae97d6ff4c70c1a4ba6727af17dbf1c57c80797e8e80ae86ebc7c394684c33f815426d6352b2f9608629ceb2f2ccdb7b4" },
                { "sr", "5e724332c0bc5be10ee613f5f71ee0cc4bc6eccccc1ce091c231c3a79a7073e05b666480b88e41fcdb35fbf2bc196b3bef3f3bb68eddbc4390c516bed3c61e4a" },
                { "sv-SE", "ac2a96e4b029965dcf5aed0f7d7e1012c2b06d54ce331219a902622e788d2b86f9bddf2595690629101d131ed9ce557898d1c85e237723555a16f073ce07859e" },
                { "szl", "6cb48f46c85beb392222bf1dd11b56c2169208c7c8422e5ed86a057fe09d47263af4a67f66e883d139317fee58cde4ef42d07fc1b46031efc1dcdbf21da14a01" },
                { "ta", "5f4a4bd5e173dcb50de2296e58e5fa977392f7c1ae02e19a8ebc19f2b49c69812e7f1e7ffefce7370c5e8276b653121f87e643ca91b8b774e9fb9167e825808d" },
                { "te", "c2e1314ae250de033f84e1f6edc40658a9321a6fbf596bebc193cd28b91eaa794e4df1057c1798c254a92f2076daea56dde7d1b0328c7e9e6b379654a2a10e54" },
                { "tg", "feef0a342bbb37fea8596fb6b17c5ad120286a8a8528867e2503ddb86d9a361e837531e3318c17e5cda3949da03efa790dfe97fab19a83c8a9c2759ed5f06da0" },
                { "th", "46ecf0feeaa963a6de0b1304241a84f4d46e6aa6bd518cd3b6df269541b36dad16a0e816cf25eb011d7a2061bcf91489e213519dba770283e3356473415ea728" },
                { "tl", "388c49950a1a986d2e69713c52cd59a4e86beee7f41b0975966b7f4e1b40d11d2528506e49c2341ea0804cef5cfc928885d15ecc183e21d99bfba1bc23e1e182" },
                { "tr", "541cb8bb07d6fd731ff8035591f14e3687f3847b0f54ee86f5b57be29f65318c87348ccb0c96bb73b0fcdd7426dcf97978ade138868faee747101b7f69efc221" },
                { "trs", "c3050c2596fd8e6ef64782487d8002b51afa74ac7f8cbda6586e8827b6c8bf2e2807de7e7dd015ce129b38b993e002b121ce2ad7ea74966f6b457b06e451dc12" },
                { "uk", "2ff376c3c01fd4bdc4551c957f8fdee8516ea1c077b021101f536f2fb96cb74f2479f3336100ff0488933dfabba9739af274e8c8c2626680edb162324cba50d3" },
                { "ur", "50bcabe401cd82cff1e9db2a5e688c06f77bc90c7b5673e83af366837591f8e1ea777dd99fccc996c93f2924d387443e4c7ff1a17c484d100dded2747738db83" },
                { "uz", "f9b9ed9050dd8136b66d581a08bbff26194a30a4c16a115c06bc956bba6148e951fa8d09e41bf4b29bc03ab872fd6c7dea8b2d634128b9dab804de564fef66b2" },
                { "vi", "63f1cf4b5a5ba4f1572e344400a2d7894555467aa86e53987a7a3442ef47b7331b802c77e3073550966ab3dba5906d3010d35075ab43e677feee59cf5a4e52ad" },
                { "xh", "edeb4814dc960477944f46ae7d1f2b2e0efe7e906559f4b2b17024c59b5c3e3907a1d0ad1aa1cb3932d3fae5c1c725f74dfca7532db3c9223cefd22b03cbb963" },
                { "zh-CN", "33c8723c0a5bed49cbeed91ccdfefdb02fe69c522d3e7635514720cbbfb7da52e0e12a4502edef8f79863abaea4e3fd9be72b2a794c28d3c31d4f7a84a99a58c" },
                { "zh-TW", "8a37a572f1c374bc8256c8495b47632d475ce94526e305e020128e6329beb088ca1aa40b0640bf57bcfcb2c96770a9fa309c6d75c2304c3189f944fd5aecb128" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/137.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e3c6d95b6b424bc48fd124cc92e994f23700edbcf4d62a020d02e154eb41760eb43f1d1505736ed6dffb41c3d06c458b49e455f328b0d3556689db22e800d3f9" },
                { "af", "76564585e4f73718e2a991d57c8c0b267f7c0e30798dce52ff87f1bf3c34bff29d3697f07707808be60b9910ab53ae64bc4d9942f1323730b3502eb6653b1ebd" },
                { "an", "647d61e9bbedaa47297be37172187cd9847e20b6fcf4e165bfa5fb3b4af41d97ab5cebaa9b8ebecc7ce7379a249e47aa31ca9a30a6de3e86b97be1bddd9fe9cf" },
                { "ar", "eb87cb575aa008a996176c6e7e9fe26b7199291a3c271c7382ef10e2131b55ddee08cf81ff5bdeb8f868c7ac8a4ce5f0da7cb798cadd9e4c2f9affb98a8882b3" },
                { "ast", "94b91fb4871eae54f43e23ac282f595bb9a4edf75a67f38ce2f69c900afb7b33acc7c1b7b38fc2db02b576dd29bb23c621e7baa13716c055e0c6d85a2f511b29" },
                { "az", "631e20e5c489145ab003a3a4f5d9dcc72d77bbb52bff2210da7fd4216b045cb55926052e288a19a2dcf33d7d03e5e9fa69e3343795b4c261efa67c9aeb24ef47" },
                { "be", "c875b64dc208994608b587c370442dcd06bd7575f2af1a5120ed68bfb971c019b6ad0cffa27f62a749ab24460b0294ceccdae22c105a7135fd80c2ebb63c1bc7" },
                { "bg", "c03458004dcfa1ad15ffe69957f099108d009bec99fd3f7c54e2943ea68fcb1966ad607d7c8fba5b82dbdabd8997327b149e28d8815387939dcb88f6ad43f327" },
                { "bn", "ad389adafb660e6440fcecef0db514378a684bf69e7de898e2699ed437507b539819318b62ff0ea4ac8909ddc88ba104ac98ffffe92d45c20a1db045d14be9e1" },
                { "br", "257959df692bff14ed16d9d127ccd2cb4aa334cca38496e165ff675340e92390ccdc0d07aaf79cdf3577f855e20099213c892264401531cdda3fc9adcf780bed" },
                { "bs", "4beecd970863f5628a29ad33e7256b24ec37f206d9637b3383a3017f58c6d0fb373724373e0bfe9d576d8bf395a13b267cc182124902064c2341f04afabfea57" },
                { "ca", "39ff3abbd7ed29f4a5065a9daa284d5de8ea9f2714ce9a45a31d450cbdb2b7c0b0c7cb046f1e2899be2e0afd460e9d34f2e5e97dbc028e2e12396b155b35f3c1" },
                { "cak", "3c1629d5ec9d6cdee2ccf15f2bd4227f1e0714a6693ac1efe778b97efc48e7766e276853873eb6a393554b6bc78950661a3b948eb9c815dfe8f0b86403d759ae" },
                { "cs", "3a228b98e293cbb0e36437f0a03ba8fbe10e6724b38d837bf1ac66d3568c1f647f22c8993f86fd4b14330e370b6d9b863a87e374b568b2f75ca9bf65be3b3988" },
                { "cy", "625b328bab726d10af6de70da7bbb56f09feb5382d0ebebd4cc52b1b0e9ec4658438ac30a6e427be5d81d912b798c0647f5bc00bfb80834127ae60634bb19429" },
                { "da", "cbe473a7bbe4e20e9116cbe7eccf6843f0e2d7bd4823b7d2f7b0035e79b3f7c1a1faee8abf838b18262e13dd4c7c0765bed3cab06c7dae7aba595586de4718a4" },
                { "de", "549aa950f9e14ec2a410de31ff06a7c2c65f86caca055cc81eea439903a5d7c6268df06f8a3c79f19b5f3b6a1ae734379426294242b3d4ceb09652e1414c473a" },
                { "dsb", "e6946932ff76b9ba90f08dc641b557b03c17c16999f9cb5ec87b55083ec7e0b57fcf1fe31b3398f3f424b9b27db9b3648d58122dd04cb5a71da9312eb0149a98" },
                { "el", "6280c39643a0685eec93326e083786a2562f80d48aa9ef1696306bfc4ce29d8647d364704a320a6fc72b28081517c3a9728c5bb27c3af9aaba67434b7d95c7cd" },
                { "en-CA", "ecc2c41f79447688e6a3a1bf65c910b65eec46bb1a8ef949884da16113cc251b4e9c66d73cd8468f2437cefa24e77b49fc77c4790dbec6954b18a41f0f8da59a" },
                { "en-GB", "d88197089cc41ae7c8f91f80d1be1894ed314ec90ff3d2205d5d3e4d1ff89856371383824f0e6304d830225262a2799be659afa64f26d9b4c87fe23f39fbf05c" },
                { "en-US", "05eb18ce2ba1663dc0cf8fd548a71ca066bba39b265c32765b9cef21cfede4f026f7cd9c03d07938e251292df9ba96ccc19e074757dd10bb128f4172dd0dce85" },
                { "eo", "ea72400bd9855b53a19f48d868894fd615ce559ca40dfca4044b38d24063c7767e2b72a7838cf6bd6dce8b08b1664a1412b97ecdb5b6fb33e7adb9c25d85664b" },
                { "es-AR", "d7a9b47529fa7884a089275d44cb4fdabad52ed425e0752a086c1a277199c876ea57a06e383c1ffa9bf5caeb051b129744dbdbc2484b616ee5c46d7fba8983c9" },
                { "es-CL", "5b47afda74be17487b8eee1f2a4cb25e6706c1d7d5aae5e83f3d8635d403d590f4bc305e2675734bd65436f940f4c9457c3b5dbe2cc8e4a55117b8ffa9ded9d6" },
                { "es-ES", "1a43b6e2fc7bc5f0299b7302ef2c8b2fe869121a60f027bf29a9f66cf306045a5bf52fbe1dc0bca239391f7c4b69b4cf1f4e583421add3d1ced8e04ae36e2ccc" },
                { "es-MX", "3bcf2ec4aaac58869f2d22b442e4d2cd80441964450d46724b3f7065e43431c2793007179012a30f92abfaa1b210355b8cc5bce20fc513b4b5e0681b41aa54f9" },
                { "et", "6a6a2aed7a20a96af6611bf47b94991cab565f8e8a25b4a615bf86fd710168932164fa4d3330b28bc8b86605fd38e10b2112dd9111d6b3ee02efff086286e48b" },
                { "eu", "9acd8bf1456421dcaeb6284832e26e2ed5834a7c76de07b9a300b083c4ac74786b38a7a75fd88e33174855e806a2a5901d8a48df82c9cd18411db099825f7bfc" },
                { "fa", "b89ac7e747235d37eebe3a2d6799963e3edc5072a02074da9869055e1bde5e46238043a3005ca2b2fe6bc709be03745d95bc1d2caf032f73219a977569e0bf18" },
                { "ff", "639fe1f81f0c06ae09d265122d9268c35bde0f470e16bd773a0f197b2610f95cd1ebc501e833d944b969938f7597248c997981a90b219be9f8382706f52f70e1" },
                { "fi", "e449e26d59ec0d291cd04c6c3684095882a04a59fce6bd78065dbe0dbbe7fbfde0cd93fda0629dfaf29f0eb485718e3106f59bdf2e5e44934780d78cc596b917" },
                { "fr", "830cf6f6983edeb5706508fc18069e85b29ed39932c02d1070b36a951d4fbfca05c8cd95c9228523138d267ac7d43f616e889bf26756b41dad282b501b138afb" },
                { "fur", "6631fd310c059b2643b8d86cbaf6dfe0789843cfd8da8f4050fb18914b8f1402b5cba30a15818c15c8288f1b2abf5ef4c0b79366ae13d4eef8b79d1fe3e797dc" },
                { "fy-NL", "c49d8f5c4469a2cfbdf6fa17eec8bf5a54abda05c00e435d4446f9cee79d2eeadfa316acabb9f68229664dd0ab36160685142510ba19c863506f28c6231f5793" },
                { "ga-IE", "c55561303be9a76e2892c6520a7cbc814333c72c439e282e4b529442d0a14642886a45818aed71145e95c178ab4888e26c13020f526dfd9b9664403a57bda811" },
                { "gd", "44ae101ccdb4bed7db32679ddd7b0f61ad7eeb970bb715ba241336cf7d1b4d0697ada52f7505ba2fba384ada5b65190847bd8910596c9450125fb87b71528063" },
                { "gl", "3a30bdd00d2cd6447cdd2f2876b26a83af47aef99a19fa394c7033362345afc7276a070fd8e2e3a607d327faeed7a298c3f66b45ba2cb772276018493efcf4bb" },
                { "gn", "b33193f4255ffa87717e9cb87bada016bc07e2a17ec7c9d8f1a2299df6b61641a970cc126ee30d4cb8b5f9bc0c6c46f6e03475095ea941a070e80abc7d17462e" },
                { "gu-IN", "46ddcf09936d9579d667fc0c33a36286f6698800efb93208ad7e0bb8ef867040d59fc4dad7e91d975f532be67b1c3a42cf22023848ab25b487b2fb18df3138b4" },
                { "he", "f39376da1e702643176d6eafe8b71798a8b260603156c08f97513ad300663c266e2cfce926adc0f31b107af319ccec6d4ee05fb8d892100e9ca5513b78d2cb5c" },
                { "hi-IN", "fc7b22b70a43a66cd83246b9e5b6897589cfd5870faa6a2792168237017413b149216bf7aebb713c85e925c6c13d4bbe6b5846d7fcc973cc6db928e60b1f6328" },
                { "hr", "6e966f038cc104aed3602dcad27acfa40af5b405e896e7f9408e7ad46104dbe9d7da9f1891c18132a9aa1493010a3036d5d232e215f3964f7e0b14b6cb5400b7" },
                { "hsb", "5b7966ff6e03bc14ee67adadaaaa6ead60cf3f4b6ee976e653316a10fa7e451a333590447d20849a5bb35f832f692134ceb6762236362bb1a92a9e22ae7f0014" },
                { "hu", "57f6f7eea7ee9127303100348fa1f310f65589d25e31635834fc3ee5838d8ea94c207507cccb4d77f874387d872edbe3e833da2df91fe7fdb9c3d169a3e32e5c" },
                { "hy-AM", "a7e63536196e5a4512f8ac2033ff520abe530654b2074d75955e5bc6eec310983c6520b82df63ff1c7fd1be585b5f3df4fe26ec93afc2d5f2143f1ce20dd4f68" },
                { "ia", "715b21aa62c1e8e7486b7f3b37ebc5a26cf1a6cf34f2181afa66c2045fd715ad7cf64478d733ed1e2d170477d3d885c8ac95a8f683ff5c5d8a5efd6c4caac472" },
                { "id", "f9eb5fcc163175a233ed9f0c840d7c8cb73f1067b65f93cf1339df5e96324797bd0d61fae8542a38050e484962c0c8a5b6748d6db0f7ca6b398164ea3942be95" },
                { "is", "8e59fa02dfb8186a9abdb3b91d6e45841be4e763f1febe8a7f3ca614d3382ff93c47f44573b4344004290d9a1e2e93a1ad63e9b14e075fc4a653cf2f4332e0f0" },
                { "it", "31e863f26fa6a15e912a7e53b6b23add549e986c222fad5a0b7bbadffa723e67deb5feadfe58e7060eebebc13f21a8df523e3cc6ad657a4393cac51618d1c445" },
                { "ja", "479ef1c9c890f662e60849e486561e402f3cb78a476527c38664d84df38f0ef8ee2de51c23f298b402fd16129b37199fc618bd3b79f935d7862cedf1b227446b" },
                { "ka", "6bfaa45efe22d3768f999feb78ea5253a499b3b6c42dadb9c88211129e930ece4abb0c688c2db533089ff899a7bf650c518ca05cded4e37de39ed48a732b453d" },
                { "kab", "dc3c71850f4809e3ff4032280491423bd1db12eb9d38f8f99f0683928160b9d0f96a8b288b98645fc58b2da44fb99e0788572da53dd55b8bdf0f3682381daf60" },
                { "kk", "4162f3bcb4f3979568a7cab44170b653a14ad852e4368ec8f921520963a2048908b937937a562e24237947bbf3a24c799a574c6561d2e0bacf7746216d9466ea" },
                { "km", "783a7bb1161d1b048fa2ceb3ae2d24e77f3ada8d30475df9d5c3e0f1d738b469e980ffe4ff8a395ba7ef3b974e02d9b97e70281f499849c38ad8a31f1ac441ce" },
                { "kn", "f4103c4ebf3a614b33c336b893ef4c61c21fbd1f6ce4215c87df189bfd09c731d478e9ed5c51fd7dfc6e2d237b898d1d8ed364cb07f3b0854106d0fa611991de" },
                { "ko", "0f6ad16bcf7352cb57bb51fc49525603e406f423ddaddd96e66786b6e4410e9caf6dff1a8ac3544828c441a5554a4b9b50c94c4c7cb8762459185af75dc05272" },
                { "lij", "f20056a458fc9bcd794704bf01938d8bc77396dbcb5ea2c83b183e11ff0a75a868882fe2713727bcd7fa9e0d14a62759ce09b19370f1f4e29b68428880f918a6" },
                { "lt", "1025bb96be1f20e9f11fa7d77a59262bf886c9583828fa03b7823fbdccb1e5fc3381ab691f12b6645e25f2bf718bd5f03e5124c609c55d277b3d6b4c1e25f69a" },
                { "lv", "f87dd55def120aea45c65d0c6cb3b0eaf4902fb3635c43876b5fb44a3b316a296bbf94d23e97f3a8cf8ee8d9b92cb8df74b2dafd25bab30bc7fcbcf78eb9fa8f" },
                { "mk", "d1a11cec1785120a0ae4a30e3031e9fb8f07e48212c078f012d920411631da46e32b6b93f6c1f587e6d992b9c2e14061cd6a08098edf38a27f4a8960d6fbc3e4" },
                { "mr", "6bb338232faad6be5ab9ee453f44e5d94e146eac42fdcb50d854bd792d021373b302cd3cbe1b5dccb01e3c428a1513bb9a923dae73cccc099d6086b9ca93d64d" },
                { "ms", "a340bddde4855906cfe42ca3fe3cd7a5578b5eb4dfd07a3509a511e4ce05ea14e48d41473d19d766410f79689c0ef640d769713aaf6e7adc0d3249c6d3742bed" },
                { "my", "9b8a524b28453afd03bcdfa80b8f04deef945580ced62421b6de0b6c9da4089609b9eccefa1a81dd6c9ef08e1487a42ed8dec716160e865f7c70caf9279aa7a0" },
                { "nb-NO", "b2bc5f214f9fbaa556e0388f30566b356fedbbab1f69410ecfacd5a8c653a632daef464fb5613c26ee8a3764c6265c6e2b701916579069b4a29a91b17a454941" },
                { "ne-NP", "5cf29b4e13ef100bdf1c42acab3d2090b93f6379337cc34e425c694e5ef04ff0346a708d7918aef4625da9951ea16c5c01a7de5e1efd43f0ee89d6ff34b7a1be" },
                { "nl", "c27d870337ed767884045678ad137e3d79c989086b79a0f1142e7a268f5732d876779b1f5bd32f33c32e812a3999fa90ad7006b25a1d7f2a0e0f74fd099d5834" },
                { "nn-NO", "6901c535f9370fa18e1618ae0bdab4ef7b4c8ee1a11e9d60c7b56583bb359662e880737f803e0bedb499917e403a59e28bce048710fa4fcf658b75929e069e30" },
                { "oc", "1605d681327d015fc58b0f5e7ae2f0bbc4607c14d6fe3742077d9fbbfc169a5a3a9c89a323f7e2125632e6c3c41fd912e8d86ecbacc0fe1267041a04661f39c0" },
                { "pa-IN", "4dbd0e68fe9a0527fc560c9d89657169fbaab2555fa5ed778445913da48cc0912a5dc994604f3205c7e44b25f255c88f71a4ee412136f67b814c73bc84c1ba4f" },
                { "pl", "24da1dfa59c23d1d55d637d796bfd855c4215b74259a0c277221cbf54b07fe51d235ed0c148754905d0fbaf7a10084aaaee09ec434459362b5421a8d7bb917c9" },
                { "pt-BR", "df3d00d3eafc8b36102c2bc4f143bee4f76197dbae1e5101252c3d7c1668f298e2c2bba06252dfe730500bffa6deb221cfa030beb423d6d905c7f1af7cd5e409" },
                { "pt-PT", "5474340eb9b780fab0030a2171f5c1494f81102d364ac2a0fa9fb05fd492867a76a466d86becb4799b6ea78cd0489a6b896c8da4e4d050738e80df46388ff04b" },
                { "rm", "78b362ec7881c7c10e4ab5d2bae376ee3a5cb2a7ebee2fc8cec584c0520b72b3fc78f7037ad910c26f40034e5248b925132a54efe0684e1d4561f51848b99b11" },
                { "ro", "4de499c6222aad1b94247645fcc87859897d80ecc1d735071ec732717424300e142e4854e4f5f56c8e08d0cbb82b4bb7ee112e54e7716839835bea420d9e3408" },
                { "ru", "9576a9b111cf127b9d95ae6fa4429be0abd5c5f4f554f4035f31b2f70114d8513090689aff206243bca702f130ff18acb4c9c9376b902f4996574fe658b45a87" },
                { "sat", "ddce0167ea0bc79e8ac3c0f897f138306c35996fa47bfa2a623d34882037dca4f78c8b3ff791e740456b4c35642cba099cbb63b8846c1edbb485ade9047cfb92" },
                { "sc", "626913993d907ebc9141cb0a002dc24dc0dc4bd3b8a0a3c55849520b0dcdf1f82f3600440159fe96239a971ef94aee01654a95b94b77c712a185080c3d884ed5" },
                { "sco", "8cdf3348ad650ffb2148b207082e10bfcc63e8073c0afff94f479bfed8be1714b3fe4a8db2d2060b05e86a875c3aeb4ffb14a86b49225bcccd670863185dc494" },
                { "si", "c723a0c52553253eaf85d70d8e9c912833a87663355fed9ca4c5048d4e6e4d72c791e29cb4841cb5637e7bef9a803551f41627bb0dcdf59331629a8de9933a21" },
                { "sk", "ab828ed7a31685407fd67ed6b43c0c54385021a3bf64f1d574a3beda55326d6ba6cd4547905b2b4002bc762e900b7d1d763162ceb07252fc81c31ff386d7bdfe" },
                { "skr", "6a4da39f638d88dbdb108be657b77fa9bf1381bf174c89c297bc6fc0b6ec4542a216f9340d3f145b50708aef2af76dcf5428d46faefeb6b06177c0c581da086d" },
                { "sl", "36b1824a8b2dfc5db4422c27508657c13f214d8926a16867bc8705e8c97f5d3242e806ba8eed685b056740ed7185f35346d176fb597f436d99602905595ea297" },
                { "son", "7c502e82501e682247bab98bd9056036afd4eeeb49e030ec2407af4b27dcc942ed01e23457359178d59d915373f414dad56d141ca257924b7502a51f0c725208" },
                { "sq", "e7f300c3244ef1297056166568e4bcd5c9f65f9cee8f8b85effc791f27e23bbd632a4333238ad3be2380b1b4aa5eac2ad2a617d675eb96a2f6fcf7fb8ac25bfc" },
                { "sr", "133db8a509215f2319a07dd8c1db9d4c0687b3d7f83cb9592bcc184417cd298735ea2968857c11d611a3d9f2b8fde81b776a8b9b097fc1471ddd4e0acaa54c55" },
                { "sv-SE", "8b68010a0b8b5cb05ee6be12e53ed64796f70f8e45529e490eca1c98eb597ea68f2884fe30d2f32ca20606fa23ed6362c97b3dfc8226d343bd05a7a50b4c4b21" },
                { "szl", "2db9e77ee20c91b58212fad44c26dd361a2438cf523d992547618b1a96a00e834d6932d516a99e764af1c193d2ad641380b7b4e07787db48a8612d8a7e0dd4ab" },
                { "ta", "6b17a7571f3383fae459dae208de8e4916fd3dc55f46e3329353fd558f3746f1e46b0ff2d6d906b31fde1a84495aa0bf6d4668ae7cfb467824732b81a6453731" },
                { "te", "602b9c5997a63a26362bdb010b85ae936219ea9393bc059de0a59a3de33a06cda583549de562b33e51940fa5d3f15484fff034a25c1b06ca279d11ec3c917267" },
                { "tg", "48a1e9a6d15deab42b89a9f44dcf831177b390bd55a26f73edcac4669db7e456d7d8b817b0e7b8312d3f65b994c3f2276b4e8843a6a5d0a4f9d4064f6d9eb761" },
                { "th", "101145014c803e9d958de3a22832130282ecde65c8d5a3fe2921a079edacb5c87404a087e002f48ece0b2ba924233dfd58ac76330accd2211eeaf8cbd08a99cd" },
                { "tl", "c4f336108f66caadc8455978f611e832267649ecb03fc52699824d7ba492e5119be441735ed7671168e00345da87415309846a117958e186f1eb2e8ef439df73" },
                { "tr", "19ee03932623fdc8d752a0b09de1771f3f20a240893e7e77b1c1adc7ec8a16e4a09e911f2a78a37cd56e638f7495087b92d36c697b74f286b3f8af5d2d32eb87" },
                { "trs", "8d184622435f10cc7aa95645c0604b8dc154daca03ff21b0626baf5f5787906d2d2aa3c527e3fd41becf44f673d5a2ba267d260d26a31a8ce76403543cdcb20d" },
                { "uk", "968a0a1c5d3f88d0f38645d35d8c9febac06ee814894cedc13a412d2b1ad0d1243a26ffbcad6ac47af2087eed54879952559a823bc5ef923a9306f98ec01ead3" },
                { "ur", "87b7657ab7f81ace238fcb7f7153d1eee1c1105721afd2e92573d37edbf45b9c52581b6e915ffce3863fa2462b21cbe856364953acfb298f8b826961c17a65bc" },
                { "uz", "72c4db809c5aaec8c1d9a362d6aea24f146457df0323b3c49a270ba3164c8194887c24b9cc6b4140eac009cfbb0a193fce15ae74efc1934777aa231734d85ff6" },
                { "vi", "885bb4fb2e37d220f6cd39567cfd51166779fe3863c6684633b52c835bafd178bc58bdae820831c350438d5723046cc475ff50df7745a63359b5027b33bb562f" },
                { "xh", "37f328dab81adc4defa43b1a519025aac2b8a6ee708c01c7a0c2f43fbbc7a1bc2a614d430aded5af47928ac79017258d6a95d19d481e7919135a500802ad78c8" },
                { "zh-CN", "b9edd4d2c5057759053d0565d051131604de417b1e340939f3418833a5f221b051c165026c4fdae197e6726bf37f17c38f87a7f4f31c5f1029dbef2972681b93" },
                { "zh-TW", "af008837e28df528cdf0320ed906b63b39ff30614d4f92c2dd90b8845c66ea9bb6986405aa973143a0f825dd9bc66083d2c3c72d2010f829736002c91e366edc" }
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
