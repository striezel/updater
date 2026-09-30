/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string knownVersion = "140.17.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.17.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "52cf5f049edbb0659570cfdc46e31db68987498777e7e8fb09d33c8cdb52492314956e8784d37be1e52e5efc6e63687a1b6728ed395c44439d0b9664f0191b70" },
                { "af", "b9ac97333eaeeb734c179490f4f634fd89c0f2f82e185e20cab67739ed7071f7385feccc5a1f9230bc37f70cb25ee1164e89223db93931acaf5ae1ef22b83151" },
                { "an", "c70c2c71b039708841fc337720d58b8e79a04d4a153fa93a627606d23cddbfda5ab9aa3516a1e680676698fe12e6154bb9138b1103dbff7e962c5e7e12ba0d11" },
                { "ar", "d4403e6aba467130d881f5a6fde64b87d56a5c188460d371c378d495da19820bf042873c30fc8ae2823b0a02cd71816d40084830b66221cd29c69c7dc03d4e0e" },
                { "ast", "331942cf1d304ee28ca88fcaba368b1de59fdfe9c42ea40c5b9bd03f00eeb813da1eb7c290f57df5035b63694c84e164652e7b33bde03b152f849e3868336459" },
                { "az", "a466b9bd06b4592cf68bbc986f7523871ec3137d0750570a473d7b48c1fd19dabf61de7d284f674ce4a45eeb2defa7ebbb47123bdfe91cd77b3e73eb7a21d8d7" },
                { "be", "b26dea0fec3069ed22d4b6d350b1146895ba141eca53f554f1c725d5d2069d6e78455d2abec7a07802ac4575f4cb667b91878df1618053d96233884ffa277047" },
                { "bg", "82b2519878d7e9600cb4f77a0701ef87637001f05507efa4b957a26a683bf45dfe4bf13fbd793755d5969c0b102b9ac64575266a3308ce2ae102ebb9dce394ec" },
                { "bn", "33b7f15d2b377147e522909e887d961c0bb7bb1d7312d454eb12d6d26d52767f3015f69820dc669da3fb25aa566d34cc513977fe74d677254c2a1b62c6dcb4cc" },
                { "br", "7472ed522237a6ae1b599cb2e88611b53ddb9756dd9cfc08f0a6b979562cc905a717bd32591f5f30e473e820e247411d47e92331651ed0c2e11f8d55db45655c" },
                { "bs", "1b962a340928a26fe62681330f8ee3e767ca33a1ac06f2c164471147e3bd4ffcfb1a3e61646bcfd01a5d4ac616fc3a4d088379c05b832a1b8824f2a2e9180f25" },
                { "ca", "b18f51eadb879c9a950ff4d7f17cf7b9a29061baed683475be44d1108864b9c7f551339115546dc2807c15d24963740d03ad3268e21654d6bcdbb032024f3be7" },
                { "cak", "975e5fb1bf4b18bb6ac3ce05937c48756532c31cded82572edd70a687089b1853829117fd3987226196ad720f0f1f72d9fae0af365cb657764896c114e480567" },
                { "cs", "60a5a6ab6cb613ee818d7f71ba870976136066ef3e0781e5d9d7313c347b9d53786beba127d6018d46d17845af85a23db1b981d8f7153bb76c52ad43ce1030d4" },
                { "cy", "aa546f78b69ffb34c52d38417f55c965f4c01daa50e7c4b22d046b244b44bab5a590bc3d9091df2f8e49e499ff5b38f94850eec7da7086ab6b8a52064cf3c163" },
                { "da", "d2eeaa471cb5cdfea9466fa20616d4ae7a6957ecd70d5f95acdf2a68188aff996a5f5c500bfb9fc7116b24159399c51189a01584f12735396794e34871411938" },
                { "de", "04f56eea769cb00e78bdb61c2fb8a5a19ef1990f8f786054e410b62366c0a60ad3f8452e6041af024767e2c7105d43522a8e5490f9d55b160804cb1cda667c40" },
                { "dsb", "48204e13a136c16cbbdf33be870ed553b3bb3d279364ec4383e574dbeacd9b6834b8efccdeb071a19795b91341981f3f0359f98a80ae2538ca0abb224e8cc02e" },
                { "el", "b246fbee678744c12ca98a8ef15895bbb9e10ca8581b0ceb5765de8c84bc5a191a417ab8db96e619b178ac5ab50630a44e6effd2c7170d9038db4d5059a976f0" },
                { "en-CA", "abdb0dbf7fa37e210fb6cb909fa8300ae5b5c80b2e1c58a16b709e5b92017cfbcd957132c402821351501469024f80f064da04b8cacb95f7e75a82e9708839bf" },
                { "en-GB", "247bdb0576b0c9f07f76985bd13c6ae39d108e6f369d8af324233e29d65fe714db49303cbc4bf85e0ffcaf70bd96a9405986134f274293115713ff870426c143" },
                { "en-US", "7e59ae59098c3ea79d7785d97a02e9d257e1cff8fa4c65611ea826723051c2987f6ef4b6b3bde3866afa29f8334e76678c09531bf98a99cb1fac840986356f93" },
                { "eo", "ca17ae6aeff5885df11b0b412e9d678bd675f473d97eef513d44b0e2f4123b2dc51d5b14a1d0958156501c539a632087fd2ec1a0651a9b91429ef3a084450b9e" },
                { "es-AR", "de6cbe4fc12309bc562c4ea7bff5afc9c890813136f71b638ebc2edcfead7619ea72f4f4e3f6834ea4f4e4c6e8bb1ce75cc1755253836e92a8e8239fcfe77f76" },
                { "es-CL", "72c6f7058e5198d082720951c19f98ef9cd9161f1b0edc0baa72b1c442977add1bfa9025f8e50f2aaca3dbab1d48081549cefcef74c27f673fbbcc8aafd8a802" },
                { "es-ES", "2d374c34699f4adeb6ace657eedab8a53dc4188450817e172fe7ba62c8849ca93445be393332bc072f21347303af08215d81431aa723ccd8a631184caa6cb3ec" },
                { "es-MX", "5958f9cec1e9fd6bbe01dd3635c25521b5e1bfb5213a4e39f801948e6fdd236b16a1195b8eef2d10f69b4a760d0fcab7dbbabb598a716d6d063ea305bb4e73a5" },
                { "et", "5155fde8c22869d3b009033e2a3c1a338d6e857e29931af7cd127bbfa8c539d8defd5729d0b2c8d2f2044401a18a302fe94b79ba8c5c5c923bcbd6932ebd3a86" },
                { "eu", "cba9dcac11f06670215b8bd07083c32d1f8c8c73b0780d4ad4248b76ff53163f08494d79241e5842141afa92e5ad18df12b22654b7bf17d939eb64b700cd8ad6" },
                { "fa", "9b639f15dd1adc0268547f3d0ebc126a6d43bde58fc04438f032e8f812c4aa0ead9df0b21a88a2970e021c9a4182611557c7e147a6b9535d7533cdbe61aeb54e" },
                { "ff", "f832bc0e71104ab066e0fe7ab40af8238a94b6c84202174fb7cec85fa4cbcfb546cdba84a2fe694f3670dadbafb4d92006ce1f2ff3474a50aa62bc14735b984b" },
                { "fi", "37306fdbf052d0438844bbaeeb5727428f07521e17c98b2f33aff69de17f31915e863fb00b3bfc4a06fe5c8f2e38aab15684d8acc421bdba86afa7e0d252f163" },
                { "fr", "be49951144882f969e7a21664fda5a0b0a07bcafe7ae1a4d82f872ffa845194d7bd35a7b96c0d12abfe006db0e6babe071487bc5ba05b1194eaa742ed84e2b25" },
                { "fur", "1360f92cd0635c5337b7eed501239b7643d9943965abd5279041fac021542da060bbef2e879b758f643a1ceb4dc9284f71540a8d6ce32d5b42ea6d90319e32f7" },
                { "fy-NL", "7dc5ebdf694bb1a461efd189760d5400f90c62832b40d05342601e33a58fdb54a4ca16558c3f9226e6951d64f023137db122785ed8791dcc191736126e162e3a" },
                { "ga-IE", "088ec06d6a33507c61e45d2be65cd97909376340723012e1749690c807355e534189d73bc028e035e034bd701b084eece5d6d2073c683524d49cc2abc86dfa4d" },
                { "gd", "0b584b0bf2d001245c2cbf824e0238befbdfc4f7a99a6a94d96c754484c65e591f5dc87e52ff63a86128c77a7783bd153ce54184bbdea34933f534c167448c20" },
                { "gl", "86666c0849180bc11b9dcd44a80e14ea1a51bfd331ee2e4a153a129d0ed7002d40e00e6021208c595d5a8b09c1d0ec8fd231f0436bcbab4ce11d2d650ed57340" },
                { "gn", "4921787f888e309256198f04d77b9b3f03709748c40359cf61fcf6299205c9f2ab0c31344a31731a96caecd73c26102d8403757ad4ffcde411b1e8801c322428" },
                { "gu-IN", "b9c794bbb264dc6a3af28ba917aa5dca9b4a3dac43845abf7b458a1d6567cac068fbcdbd6657d02842aef3f4dcc804862fda05d3e0ffea5213c0415b3d3b6c63" },
                { "he", "daa0094ddb54e3d574425a2d790476870cb302d6a43c78e9bd811a18c076d70e5d597dbbe6190b7248ccf599e7f3190f05462531a2d797780efa229eedb8876f" },
                { "hi-IN", "99ed6a5fa0d5cc073681e05a512cc418d4140bc07448df08a01fe7382d08ea4fdddbf08de90da3b03101e28b8034d9bc1c39ac0ef02a499448a53bbb20d68f92" },
                { "hr", "83ca269f14657e1b7158851ad5df0f259332fd3a89468e36dd077a8f4dcc2bb23a44b1c958b954210aef32def37cd32212d4e881a76d2771b4c52f71dfae549f" },
                { "hsb", "d511dd873e2d4470fc471059e0d5a0a9168ed3f5ef4cc3954ccdbf07a79d52109d9e4e0f62d17a07b0fb63aac7a617e364be416bc1088df6e7ec8717c5d069c2" },
                { "hu", "d759b2220c093ef89bfb2146bf9aef83939445a43c83edc48f88c6cb9e0347fb4ef13414a45960788058485594580df35501d14ad9a687d90e7f2ecb8679b414" },
                { "hy-AM", "556d9280041afa364701a4aa6d640c1c0f7cc1ac6cfb835810687d03af9df40cecd7d52c61903673eab89f16ced26494f3f31da694f058db0b33241380cac540" },
                { "ia", "c9b816459c1f719f284823432039fbf4fc8f04cce28513ced9967f8906946fe2b3d170b8d1c1cdb2c036805c3bb5ee6cfb3959fbffe69e759cad159790cbc0de" },
                { "id", "d2f4e59387ad844d69241f6d51884bf60bfc4e6cbf30ec39c74153e9df8a56baa09aaa6a01af629f9a434c698278bed464fe412fdb2137fcdc0749f825ef004c" },
                { "is", "878a98cf26c404b8f7f09353eeea4c7307f44a8653458270bd3ef5e993d96d209aca1ad47e80292910c91daf61314cbea76979d2286a94fea8023210a5784c65" },
                { "it", "75c41ab20414c365ec325cf2887ea349d4cca7f86341d6ee4e5ca9aa23ea3b97d3240d4d79ebfa25b965e80673a79d7864c0767305277bba22828b6c91fda404" },
                { "ja", "3988e433e887319144daa3359b777eb2aa7467f1002d35c118ccafd718b343fdb554ca60b06139909e7d8612c9945a7db80aee487fa6ea2e39c8ed1e241a2c43" },
                { "ka", "18c86f3dae7b5cbbf8142f3d5d8c8b430d128e91109d9f8c1969904c5c12c690787ee8881ff7afbc8207742ef371b33816e970468f35ff219c9002eb5e6ecb29" },
                { "kab", "05edcdddd635f975c8abf3b3317e9a0fd8b917dec0d361a7f5edc3a7a84a48108e26367edb7564ce21d6c471095186dbf8959a97c395a452c4d04cc949f8a8f1" },
                { "kk", "386f6535e5efbf5d635163e9783215c0107f1d4ed5180aef2cb515953a2b7d5808ee9f9466cceeeba3a522dfdd54bfbfb59647722b285211a86b2606dfce2abc" },
                { "km", "3e842ae4f5df9eca2055e9103736c621cbe21d649871054757dd4474db9415498857c7d6004dc32fc4a7ed7f87e9d0c319baa12c366a3b6bdb3827200d298513" },
                { "kn", "d97f0eb8361b0ea3beed6cd1620992fa9f8c5865eebaf5606b947bd2d1ba1afd5c6ce4c544c94e2ef265b31c874a4d07a144b65dd87338d7324ef443fa762c22" },
                { "ko", "2f8e35ec02e3b35bfe2be85c0cc644ea130bb8eaae048e41364119d0fc033926dca12b09762a043545e610927397ea08b14746ffb97c9d292500d3e862340346" },
                { "lij", "3f960241759baf19e69095fd9fd97d6d16cd782a0dcf256a67b997367e41cff3442e92a35b5d863346f559f6fcdfa6b51014c883d7d1cd242621f3792ab1dd6f" },
                { "lt", "df63b253341d798187a26ef44c80accba91e190862f3ca1a797c3d12d08e30d057293ce7365f98ca3e01b7141d67087cdfaed0b86ab55df74473d4f77a92cf09" },
                { "lv", "86adbc5e0764133c24c073ec55ee7bda730fcec93fc4cbd5d3b10fc3ddcc52c0b0d4b835f0ce017967076b5b669a50e5a0dea1e180ccdc056d2b05b44c41c3f0" },
                { "mk", "6f0ac318ebf33502de9d77bfd2b341c90634a87fa432270390b7513722fa9c2939f2839aa167f470bbc1c77f6356372cb7a3b77341e1cffd6f1a097c28a2ff0d" },
                { "mr", "0ff7ed0b3ae35639df4dcfdf6c1593bec4b36d8c48c498191b304a7f3e35545eafc3b48286a1927effb84f770006b7449eadaa41b1b8c30438c12230ee4a8045" },
                { "ms", "cf0acada88238eb3800448cc762864d5488aadc3169376e130307b26a72ac061c2c298eb75ce2b21e195eb71980e8c889f3024cd20b0db052df9d9ad23dae413" },
                { "my", "58a889b3b0c17ffeb6d57d082878d46627e47bd95dd14dfc5ac7ab51304b93a22878794717f01a19741763fbf35cbda437ff839aa766837a2f3c960eaa6cfbf6" },
                { "nb-NO", "8040136603eb209a1d28b95e050f7a1fbf3ce33a6e60521c247d905c2695effe1d54fc4a6dcc7de328b5367f71fe02a92ae9f1394744311862523f7dd0750fbe" },
                { "ne-NP", "df31aa47f62cd7a4bf4d7b4accad5b21345841bef6d723e7b419a601ea5758aa5857226b27865b340d03953f9793e4159ed46bc7139eec5030eb87b6856117d0" },
                { "nl", "f3774c2b397ed952438639eca7af7a72d04ca4828d88337477d370763c6c8d6095b3612a2b16fa92d9ffc3a5e1eeb7eef26d855e8c30d3d732d4f317deeee86f" },
                { "nn-NO", "652647a3635e4a88c187ab1561bd437a6b22899039b8ac397e02b3c3b8e67ad1fa5f779516c8af49f8fca4184baa68a7142f180483bcf4b354dcd8e306fea7ee" },
                { "oc", "1b70a6986a38be15fd431b6a3b2b4516e64ed67fb7438d9ff96f888cd9f1e7ba7da8e84c1866aa2887a7ec9bfb16c46a5ff7eb17cd96ab30378456507a192847" },
                { "pa-IN", "77e7445cc5261ba92c5ad539ff50a5bb20208e9fd9870c85b89c80dfa627260ca610fb03c00a586cee40ae7e0b0afb976f0c94e441e48b88c63345d19a2b0e26" },
                { "pl", "97bb60e8b723ed63621b61b3bfaa31ed453de01f43c95d7e26176438df5f77c28c02b9b14a01b1294ab6b7116b2cbf182796ca2dd74ea53a4d764a76d245ab41" },
                { "pt-BR", "7ec09a5f82f864e39e7895230fe633bb7f06cc2bda8e33289d69b1b93eb16c4da1c559385582d363b3aca115e05b182391b361f9bdd4f659be53d7f1817e07d3" },
                { "pt-PT", "01a8ff298b4d9d453129d926217a31697c990dd428a6f7ad431d9ff6ffa6269279ee37516ca1b2025bf8f1acc66422e37b7efbf317481a6221e09fff6b1d8b89" },
                { "rm", "ec7ae8da1511ad21f179399f45f6c875b2c17c008ab90c6c618e83605198552bf149cac0648a764210295553307eb23015021f9e641a89c4311422ab15c9accf" },
                { "ro", "5a9d069404f9eadd92f10cbef08332fe9916a98d8a85ea7c0cdacefd4ae2dce561bd6c3414d8174b1188727701b5dbf3502beacb615bfb43fd6f7bab0c85939d" },
                { "ru", "3ea996ae9ee384bbde31e56a2049e1807bf033abd85bfad32121c71e6870e65cc05151af69f82fc2090393739625a301977fcfd57594ced18f0263768ceede20" },
                { "sat", "1f6429d73102792e25a24c34c689fd85d3af796dd1692bcc949033ca06cd230f37a5156953bf8ad2a727a8a965abccbf5da3387476ac39d212c8fa9282075fcd" },
                { "sc", "4bb151d24ce32edc2763b17a7fce77225d5889418bc6fc6a976689626edf43a54da8f6bf90b134e8504d6644989333b5aeb18d2e8b401b87131ac7f460779e43" },
                { "sco", "06370c065dbe75960e4f2732a4428c7f23cdb058b101f9bd340652355aa388e3ce4fd25fd54dc5faa5fc9c15a8e996f73007c0b41f83479922babebfb2de6ae8" },
                { "si", "07ddde5ed5939b59108ae4be319ee01152a438f99889ea9591b2abf8ced5f169ef92632369f608076af3eaf3dd7a598b3916e458d17d454a82b4c974d4d74e59" },
                { "sk", "2ba4ec7539ff5adfb82f451356dbf995070b2d17028bff450c6402d3075031ce2792237b8dbfebd1fa95f409b8eebc8143484e8800301f4bd80a3c4e0d35dd4e" },
                { "skr", "afe47a1df06000c4c03c976ca07194da93e71de29460867aa54da39368ca1ce69f89e4cb3a871d99f7b9794968a9101bfb00382702e491bb726257f86be15df0" },
                { "sl", "1ff2dd8b1ac068281f60fe42e7a524eff5ce427b91360cb148ca3e48bc1232eb63e34c32ea1ad58e17de50cb1f04f60a0df0e55f1dccca6b46fd8ec71fd1d8f2" },
                { "son", "1ab446092dbbb7b5998ccedf47ebcfa7a7ba99ed75fac8fef2e8fecd27add81ba4005cf4888367e02a368131e61e954e6e8e46eead67e18a056c7668c1c68a8c" },
                { "sq", "df75fd96ca072961eb45d3ecf30c6bc97c20676e5081bdcb5ad0fe8bdb23311904071b6e405a8ba6cb0714ed0008cb7bf64c96631d77182ca4b81baa20e33049" },
                { "sr", "eff879631b73c4be960d64d200706421733af5041cd003be8602c577d6a4a871dcd5169a925b304112b0c868bb6608c4bb89e5cad3d2c68a2cce0eb65ab63549" },
                { "sv-SE", "c6e105b575b4e6ac71866a1497dabc862a988d1ec85a0bb2bb083fa3d6ac869543b9285d8e3ee401d18af810ea4f27a88ab297883229a72745ed84cdc7b37615" },
                { "szl", "a1a21df03caec1dcb4b67b01b56a0cbee17e6126ed472d3b28b770ec86e1d1a95e3bc28df039062036fbd434c7f753684f524db377a1019f7b7da68d053f8c0d" },
                { "ta", "fbba91849fabe63a7b5978e02fefe00d3afa3713741f4bc11f0b46e135872e4000c0b0bcfb7c82509c3b1920265dbf2c273397b5164260aa8394e5de4057539c" },
                { "te", "eb6ebbc13fd1be40af823b230d4a0751fc7c6d05929582d400313871883fd58e7c97e95f9e6284d409a4d7030ab417bd57b9cde57170aaa5a2b99d7a21470347" },
                { "tg", "c5ffbde837466b8bc3f946d30723011d532d45b80029860307c823375d4a47ed1b96b5cf34057fe34aaba2e5f4e41d57bb568d72bc8028bcc2b18cbb8c60a99d" },
                { "th", "7c68d4e70989294bbd333eaa3dc9ecf4a6b96da227b76f3df90cffe80c7f6076d10ed290fb9ca0f3dadf8c72cbd6e2c0110bf999a3dab57ab5ec5c7db78709b4" },
                { "tl", "eea86e2488df8d754d24a80e5e104cdd4cdca157d9e7a688d86c1c703591caf36e8ca1946c6bf79ef861298af38e4d9f626e5d53813ab76310137d23c76d6b4f" },
                { "tr", "ee2d383d0c2fc34b532cda67185446bd58c739a7a0c4dc7ef6d457cd85c3e67fa6ffd5f3fba82780225c8effdcebc8dee3a442a2c6966bb54d33026bec97b461" },
                { "trs", "9441ecf0961eb4362bbd6d53adc0392d4dc2b7d7e4ed5515d37817440eeb0233705808cc150e3d893bdd54dd808322cd237dfdde0b289b3eb8f4cd3b685b5443" },
                { "uk", "2b997a9844d5c68e7bf1575a1d875d38e2ae7b0639cd6ae5bd2d67b059a416f6f1d8a3e5f48b7822f66bb08cbbc60b19164bdf4f72f34bca619093c60d006bf0" },
                { "ur", "3a556502aa9f1607e5091ca6607258f8172a581a1b5e74e9eeeb92721a47337befcb63027e657201475514e4c753b56fe88f18971b5600d16c52dc1532d1ff80" },
                { "uz", "1d7adfea9150154bdcaff0c141378729ea38872f0ae6fb665ad4afa6804783e3e819b369af13f28a7082e5f5652abd2725594aa9b6ebcf51efafcda2644055b6" },
                { "vi", "38bb7bc8e97d0069b41b1b8d75294c001ba2765f6afc10bce0c5bbb447b6754891843d47431e1ca180031ab65a635258629c4988b192cd12c2f5b4970834699b" },
                { "xh", "0c05805cfef36a2305bbd8c48864a1d5ef948973db3028b9b36a44f4e4edf88ba04a14675e50daf3fbf3f617fa98f942ea40163d991bdaa426d252a5c1c99404" },
                { "zh-CN", "a31e5791e37b9729841631e6fbc5db5c0a2a5641e606c0f64cc60e014b37a1dad562bf8769c91ea4e1fe87bf8628b97bc45542c7d7e3151c9798e7933cc8d940" },
                { "zh-TW", "0fe3ed3fb2cefe774f1c528c378a91651df568c53275c9711c0981a148d88d0e283c811fe4bbe4b41cd803985b57e0902a7d34ff69244179abccb60438eea5e0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.17.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "83ee2961c490d16725d966a790c9fe37199eac23eb38efbf98f510533679de1149d43111e3a1671fbb283562fcaeb56449b1afd972bdae5ba86a0085be67dde3" },
                { "af", "5211ae67a2b66b430f11e3e67ddb1e6ab394434965312b822f29d580fb58cd5f84ec0cfa767cca98dbd079c8b447e87526e25363727ca37ccd328bd6a9362b20" },
                { "an", "baab4580c580d731a00a8913eacb5309363fca09b4269bd5dec4de203f8c14cd46e12dcf30a8bcf88379c550a1f3bbc422bb173d811dc3df0be4ee04366785ca" },
                { "ar", "8df77efa94944da840e66dfaa345e82cc2658c2e600e975885b281a652995d88cf6b61e09cd3ee8d962e6b4b528f55c3dddd57a218e2e70e9aad96f58c25cdc8" },
                { "ast", "7263e07555f19d360e9f7449d11c39b4c5fefedf144b1ddd00a740b6f53bdd5a317a2ead3fe83f9184c2889e44e4fae99856cc10d029020ab753a77cedfc80e6" },
                { "az", "289ff5fe47bcf291e32ebb8f801e0682b780238819b2af5862966ac73d862b0c48459195cde24913a463ef0dd41ee1ded52aa43942e6367b432ccacba1bbfb2d" },
                { "be", "cf7dafd2c3428ac6647943bc74d739f12b01ee541f7fcd33b7157a94509d82bb161a1668746cc98972e248558df7dabf503b9bc89af75e3dc85bf8425f326ab1" },
                { "bg", "97ccea994ece757f728065c68f24eee94a821e56756e984408e77c8f414c414cefec5aa814279942c50f5ef20c32842cf6f1cae2e3f69c2bf2a990be3883e0f4" },
                { "bn", "293e4584a5ac6540d729b76645a1844cd37545280dfab048f42ed82ca86bf58a1a2a8accfc8ec4908ac9b14f585708596b01e5f7bd635b6ea9034cc04368f5da" },
                { "br", "4998c76548dcae9bed1860e4817af7614da7159661116477185e215c69e0d1a058640f4be9b9af9dc81c9b116018a691f28d3ca8bb2d41c3f4f4bd43de85c877" },
                { "bs", "a37867f53277d3322070f5bbfe3834a738015178d49b2ee9bd671bfe7bed048c9754a6c375654a58f3275c313399128e96f1faaa5487d1c449f8e9adede3a41a" },
                { "ca", "e418d530e251d2c5128bf30d4404792b58b5685332d016ac1bd5300872e698f9f3d9129c11cd53eee2685f9eaa3324267a3c33ecb2851c80ceae111ed856cf2f" },
                { "cak", "7b5b59d06fd2da78149a1089e03f3021a97b0a7855ffaee7fd55b4b4e9e318a891256cc22836751beac954f8da657131fdd9cf6f4a30f4041eef884de203bcd0" },
                { "cs", "842b9422cc2dbf4fef38db4fff8e70450fe77fc496f8804ef18db9fe639b4cb9f91301686cb5e9854750db37facdbb284a73f4a6d4ffc866a0fa4c103e25a7ec" },
                { "cy", "56a10b37bd0d73bd854b61bbe8599c27dd4135ede2aa6e6d61762e6f31c75900a32c7e16c7e68c952c340fffb996a0944166b443abb5ac683d27b13a6a1e4a83" },
                { "da", "c7fdb4e78f32ce14e2a935cd57876d21f19e40923eb38609b320b7c22f56117bc2e937019e611f50feef610e1745c9bfaa17d7c38a7c3b4c4b15d034afc242c5" },
                { "de", "100a5edc6503afe97391aa344a53c6472e49aa32dc6ac6f6555a181d99e5dea5ecbd50ba80e7042c4cc9ae2368c380e48918f894518f1feee976fec5bcf51d56" },
                { "dsb", "520e520ea48634856e045613f995a86df96f741be22698919c4d7c373636f62337eb86a68b1ba0bb7a2c118d7e90cd16a5bb349e855a5f03d4f03f609ee117d2" },
                { "el", "63c63a147a04592927f4dc2b88d6e1401f4059f36873f57700714f1c52294867c791df1825ec04b3d1937feccd7712e3b5d822d50659ca208ea1c15264cba932" },
                { "en-CA", "9726030b7d0523b70ddfa2cb3490754c2f563620d83d54e8d69fdae59cb71e3a88e3e9c6de0d63fd8c96385f850980371e1500d329e2393bacacbf46a4f68f27" },
                { "en-GB", "a5ef736e4fa2f549bc4976469bbc6ffb2ac8568ff6356d12a11ec900bfb89b15560ce777f90a4753e76f716420715efca3e7d8318faa194d4713b2a168a75d25" },
                { "en-US", "ee4f3cbe72db6348c86caa299fbaaf83de152813deb384219e014b6c6f5f1dab90fd2b2df16a9fe3d5f09db18964f6446e5377a3166aa43a65c9bd2b90dbaf63" },
                { "eo", "4c5461af31708ecae1053d3b03acf9d2f0afba21a427c50c6922b920252689987dfbf8440a01831365d24a3dfd9cc6009a447c717f42f1ce6c08a2fbf408f2c3" },
                { "es-AR", "f01c0a241190fabe189034f1aa02c771ff8a6d306dd87fa3480cad306365f389a33d22c32041f41331a777523977dfaa1fad6a7c6401c535e4d8998f15ad07ba" },
                { "es-CL", "219d79dbad6c853ab633420fc409e26a3ddfe2c1291b16d4ee95261b15237a7ac71748a8a6abcfe0651d91f0a3b350c37c8fdea9edd0b206dafd38f1381a50af" },
                { "es-ES", "fa7b362921b7c896c8b0e4947ca611ef4c0fa164a678a9849b5932931aadd68abac96fefd4db7de80717205602a4d43beb894760dbd23123bd907d78410d5654" },
                { "es-MX", "8530dc13292013249048763a17e1d9ecac8aed2f377925b90a9c3ab4c29a32aae771f3d1af2086970a831c6c30f6be7e2c731f2b49eebe7527feba72d0ec5543" },
                { "et", "c9c9230ab40e0d96b788fd821a126852b06f7073a79f4d8963a01b5e29efcf8a607821b0df8b4ea9706de8220a9f6f8c9bef044c15b1080cd135a3c19bf969c9" },
                { "eu", "22b875a9f0f69a7a5d59da0fcaf320f36c1302873484ea877bf14a6edb7978b27e7736d16fd92896caa05c880a4001ead1f5443085fce61229e68d4294b7417b" },
                { "fa", "406e753089481dce9bcb48ea3a8475c9a501ec551496a22b470fe18c2b7e8342f73ea6d0c6c9a46535fc49e9280360b0204e0a07f691c496ecc87ecc13fa5a01" },
                { "ff", "6ef5ad4e68a49b5930d9b20758086866b39d7a90a6adefc2b4c0c743b42a0a805c7a6c92e1a9e2950e592f9cea3f0bb05cf2b2af38108ada31a903328a265239" },
                { "fi", "930e23c7c002910192e564c9890b96bd4cbdef47dbf7278382d0f2d028bfb3c9b81506ab17d8a8d60c3c7d5c37caef42a71ad1f2db47138ed2abc7a30492b118" },
                { "fr", "46e8c0b093850723058a28d1a939ca6e7f1fdcbc4ffcafc037bd4062ed0d366b2c814a0e21cdbca3900fa7c60d62bad7856c164dfdeff9779a3d463d652a261c" },
                { "fur", "ae73e511ab2a49fff4c76bfa337c1993069351345dde6b267d0185afa7eeba7e6ea4a180514d47a6d8b66813f10d1c26e8e4fabea00542a434a949670b893790" },
                { "fy-NL", "ba8bdc2a24780d110fa239384448f8f6a3333e52214805aa7d46e7aed8ea92a2d2d45dcc43a5547d66f5e0ff588eafd3dfa89ca5a68b6ed204813c463e4174e0" },
                { "ga-IE", "1859b926eadebd7fbc9786f665a0af701f97bd637c745d71f50b591a4ec4fa04b526b9bf17ffc5b841bb76af860b89f64097ca6e8f34a3cfc5dc03a2f877bceb" },
                { "gd", "b516fb85ac6927df0a059c9fc11425e42338eff69b00458b28454f01395e65348ea2e38c801f7d503672bf0db3d34b9271200f11cf4565c1d81ebd839440ba6e" },
                { "gl", "8a6a11e38df92f9e92e036056f27517dd755614e849c5d8b7fd93c49a11665ae1ffc88e74d08e5da37cee414c99a79bd02b4df2a11b8f1651626067a5912b520" },
                { "gn", "9984e53bdd97b2b9e5a2495accfe8a32a540fb202ee94c00394e16063a5c9daf33759df920f1796cd4f56ac768e0b983420cbd85f3bc172f86dbe13ff4973a18" },
                { "gu-IN", "50af622bc1945fdf6f3f23bb0d00cd7715f3e6489e254b720598278377205b46026c169a4b35fe5ca6730717430f0e4ea476a621db29b9d6b90186af3ec4f600" },
                { "he", "015b97c339e328f7d6ae1af3e6839a44b341a9ce76c8cb83cc8b2e13d9990f6a3db8ba35e6f11e6c8eaa0752b11e6727d8c9da291d388f691086264e2dbd69c2" },
                { "hi-IN", "627ee420ca43044548ad3fc4382afc99cc7ff1f74c7d74c04075edf879470c1b6cd008a9742686c779e163644ffe06e13815bd9cb0790957d90da096eb9fce65" },
                { "hr", "e3fc6b260615ead2c529b737fc7e8beac8bb48d75a790acbc3078deb478bfb1255fc33cc000609b126683b0d88c0013071aeb3c63c5e659671444ee83d429f16" },
                { "hsb", "d659b84d13402276b5d5866e6f44607d3c27b9f52e25dd3dff91ba0b712c377d506f67bebd9ad8b465ef3b0835b6955fe14bc9b290b60d8171ca10df2661d75f" },
                { "hu", "bfbda97700970f8a437385811288eb9aceba4f7cc6d17ea288b2dbe47e292cf648b7bd11b925378ac2ab7d1b33ffad092c314dbe507f799d23e6b6b9cd5b3713" },
                { "hy-AM", "431b01207477f82d58b6c8171292610388855d89b77e13a2f012b26bb0d2dd8e05f351ce80cc20c7bd2a94b9f6b5765211a76701a269b4f97bf2dd7053cd6b1e" },
                { "ia", "b24e32b6355bed04018dba833717a18628bd94340eec927b68446412cbbc29aa4d4525ca488b007cc9b9ec68465e27d5c8779afb2cee5cb2e8db41341a362de1" },
                { "id", "483e6885a58406a386266e075c5c25e9f4547fa3336cf3f6316aa338cb100230c6c276399b605df8403f58b61dd060e9b75a4f82464076cfb9d7569e78e5a917" },
                { "is", "72bfe5437e315680ceb1d9fe3520574471b4fed4013c745b57743f0f663f23cb3e7c36eaa333e5c75dfe8f7f61948b7c5063018a303d178e2f4b32473edf75c3" },
                { "it", "3797b06ec3070db180845da2899161568321d1cb33be40bd996e935c1aa0df5681fe38115084f521f3f04d7e7ae4a13299f6674a7355159633aaf7349d5cae86" },
                { "ja", "b16a07b66bdb8eb8af3aa8e9121eb7c9b2a209972379b162c15dfac2846097c8485639ae6b45cb5c3044926b1ef3059df0ee35dd6a8e395044f8aa0e3819a219" },
                { "ka", "c8d1adad496b4334c5d68d7f42964b041223af4409a1a77ce384470581f1676f8c2622f393fcffa9c933621540f4060ac7449ceb0c8e0c734e5528d5f16405a5" },
                { "kab", "966c10bf511707fee7382f91966d81672d61e5947631a01af2c129f5d9116e858af2575c70bd20792ffa676ff572ae3f453eddf45bd26184bdd102e02c485e49" },
                { "kk", "1537b165b8a4fc139ef0854cd52b1ef66b2beb09bc67fc9662b0c46fabf2ed09768a5786b2cebdd2544c566ef8d65c2c7c096978242a7d5824e352fe6d3397fa" },
                { "km", "a577801a1342a46474c2d9733db8d0703c9f2fa2605d17344b47b9026c1f4a2b9785d9ea86c6153186c2c449b1e64fb652d992356ee853f9b31235f191e45dc3" },
                { "kn", "e9ecc65c9cacfc3b7c9093b073254d22e368bdce9533559449c9114a5471be72939c345fcedc5977a9526e7bafe4128d97537b2da036e5272553a161e1d28331" },
                { "ko", "6cf8657323383fea1ec7630c1f09b1ab7198181f7cc6298e084994b757ebbb5baddaab8f1b79ea249158c224a75d0847481d243e5c04cdf5340dae8dc5146a07" },
                { "lij", "0a5a1660c14fa85c5a296d66b7dc53cbd491d3a61b0380b9032e1c03c0924a5770ed0f700838193f38f8db9ee1978ec6288d545e5533b1d12490086d6da8daf9" },
                { "lt", "30b6a0c5c9487b6f9365b729de18bc28c994ffbd4ad4b2cb0682f43bfd83b04146ea8f7c7e671176dd8be4b9e77b17e65c980d1b2b184e67aae31729602cca20" },
                { "lv", "efe2418210f782313d41fb5e523a3799cba5bbdbf00db12cd4a91db3676878e28ebe89d162984a3d5152f7255ae2a1f90a54d864e7c61c01faac1c15b3fcbc27" },
                { "mk", "ea68979ba494c5b2da8429dd6518d8644bbfd68bc713149256c57d62a86e3a07b70032afa00c23101688ff8a60aef05b0da0ca7abd33b7d119e6a9d1643f63bb" },
                { "mr", "f8d9b11b758775eda4015e75c34d416848eda4fd3c9c0169b1a054f6aa90f4fe718951212b94e55e1d7a0aa11da39dbc483ea71c9c744cd5177f1d8a15e7f25f" },
                { "ms", "3e6675430b85d6f15b6a7ff7025621183baf82d5a5644c5d92cfe3943231521929735f694accfc10db760e3868846791e231edc7c84668a9d53773023af6eeb7" },
                { "my", "b2b8e49e95fbd69175cbf3564dd04e4269efb387db2186d9b03529d4ed067b8de8b73859517fa915f787d77f7c6245f1d2c552e33ab1938c105c8c36e25d6492" },
                { "nb-NO", "a5956d6b87ac35a8d8818b977557659459611865c726ba0b88759f90a9f76f8f4ad75a524cf3eec948a559a12a7628ead1f29eab85fd35a78fb2420d7edb1dc3" },
                { "ne-NP", "1beaf874c1266f61b3e3a431511c521bc4fc8bf5ab101dbee47f2eafd8ca114feb603dc6f7fb09dbdcc8c1eec5ecc751e4f599c10b3f7d03f600914fe57ce431" },
                { "nl", "7e6a87b0952e9aa9117c3b91e74f354ae269d4e2c7e298b43a2690379d9f4a3724a8bcfb76a26b416cb6fd66865977f82b029ad9d69e03be87ab1e0b6ebb37e1" },
                { "nn-NO", "cb5ac07fde9bb4aa2b2fbdc44753a63b1792dd9358df321540ef247d8241fdf77abebd763a385a5166faa31ab740052eaa441dd8740e29ec28c1c50dfcb7c2af" },
                { "oc", "29aa42fa155c30c6b945369ca3865ddb0bc59b48f0417d9b79a4689d2254efda1a7c116c98d605184f4df898d32b1b22a06ee4acd7a8d70ca6cee9deda34e628" },
                { "pa-IN", "998add0a2d75dea29e8ba8b21fba527578c040f0637dfd1d0b1a760d45ae0aff1827cfe555d60af8276db078b2a8389a52988004e186becf4ae3ee1cebd0c095" },
                { "pl", "ef0d394dd9f7af44b40299bfcb1f9cb93a5f2cae622e320e66f557f7c81887ad2dfe453917d958a4e0a0b6d1dbb5f8a8caec50ba331c0b34e42ee2cc031c8fa9" },
                { "pt-BR", "aeedc1d9ab9a32b017eb46bb1f5528c4a0c7d97748a44ccbd7d6fc827a53433c4f0a851f9cde2b59651eefc7d928cd7b808ed7e8a99db9e77d03aadcb0cccf64" },
                { "pt-PT", "b9737644a8df07576fe07b10fad26ee4d1bcf7926e2d0557daf686e60049fc64fc5b81ba8dd957d7208126dbfff3741743f1d6e39d9183173ad0247c615509cd" },
                { "rm", "930aa7854d4502960316d750514a12312a84aae45c69c8e4731d38542c71b5dbad51d7f09ccde43cac35eac62013200cc70d8983a78fd44a992980e8a6a3e6ed" },
                { "ro", "97113d89acdec5361592f2679ae6d043d7641d5c61a97798a142def9b912d26af4233ba6d88e3d57c3a359dae0ba2ce7bbd82f444eaea373fac7f35ca85fe2ac" },
                { "ru", "e374b22d7825c5f7e177f469bae873345414d2a96644d70570aec699ebf59ac0e023a61390dde02fa4648918368c4db2e9255ad4334c5858ac21017afeb777ae" },
                { "sat", "0f72135e9cf03e0d4dafef4cac1b1c7d94c9a6d70ea1b3a8351ea4a31d20829c60db540b430c2e26bd1b8d04d67072e0194dfdd9a686abbb44c364fa2b8902fd" },
                { "sc", "085624c68a8927bf7087cfe0387fb343b14409f445f2e4f3a252de22fe0fe7d04b0e131676d10856d68108480140b31f3b870b63053e09c0437e04634ac39daa" },
                { "sco", "bbfb20564f0a7ef5368ecfd5e025068102d1b55a0fbc7f59f5504b0d718f3367b1ced4158377a846c14611de91483066bf8717a5b6c1b1198924b513e7a711ca" },
                { "si", "f7dbafa5817cc86a3d5734a567239b88e125b91021895d8bbe4bb23056a3bec3883f6d5cc5af5208d3ccce91645ee0e491fdcb34e228f264771f690c70113e77" },
                { "sk", "1f3fd1e55c5499c5af7715cc0308e8e3825c1ebeab58465b4731fbca29f0976e0bf59c4528df07c7a9ced14a44c2ff983dd17460a6a6c0abd7725d9ccfe3cd27" },
                { "skr", "f2586b8859c22233e671a76874aba4592cc4740f0652ea436e2e49d3613de67139b46b1b4bc1b67bfcc67cbdea577ff253a2c0dadecae97dd3c993b95e0f73a1" },
                { "sl", "cc4cb9cf3458b5e44198483e65d9d50579a574af969a1ad1af8e76ad1ec068de90565e910b7d75a8c376d0ddd712f002113ca7f9c8c3c13bc5d025ec9a868c34" },
                { "son", "8d8db7141645d0de3f94d6a98a044301d30668d1ba0285de689dbd36bfe50d4821683c265f7a273d19f75634af18556be750527dba2b4213c009ce1189286f2a" },
                { "sq", "7d362fca706e5bd83ddf063f32f132a599bdfc2151958965e4a954908fa1b70437967b778bbf904981ef21f52cc6bd873245c2132600420163fdb0ac89c9dcd2" },
                { "sr", "a4452b11401cabff585b81f5ed3b285dd7bfbdfa0e64ccc18b1ada8fa272801970c4256c39380a1554a6e866aaf2ea94c1962a8d8739f278d9dec7312eb57dba" },
                { "sv-SE", "f63cd9fc72d6121a80618d23ed9ec8aafab5ab36019b517bd5966034df377b439982591819851584d5d4eb8879d9601a266293b3035c18390ebf514419a84549" },
                { "szl", "06b8dcb69a3c88aab63217c7bd887f33fe87ac6e57d08eefde86bd462d9bd093d738f9ce2c20eea27d94cbddd6cdea32d86e1070fcf1699a11ef39198ce184e1" },
                { "ta", "aa4b2e9b7f7815dc1e3721da21d49570c25a9cc05726aa0960b4e323e1e9ab3b9ddf2213e28432b7900ce53bc7463b3ed224f0f10b6e590bc2bb3b19a7e16fcc" },
                { "te", "837ce26c9b5311e624cf3ab7566b2c9c652ed5c53d0dd6fd8f281d47054492f59470b54a4d085f08e753c45c7548cb97676d052fcc91ca46520972c35bf03cda" },
                { "tg", "ece64c8222aecfd00ddc9ced8344578777a742cb1b218bed0fe4b25176294521773be3a7a6ebd95e5ad16b94ea1e82274a7f3d96504b1f7c67b307733179892b" },
                { "th", "17cd3f828bb3733e4107167bd68e46182eb563ea2615de58fea26dbc9e1a0a326ae32be4a0c54e6b5291d0ea6dde28a9df1a5e8b93f5e64d582b26e541795f4e" },
                { "tl", "c2958302b3b4a4dd6de96a35aaca6bda5883278c127ebd95c55487e1324d21835a8a5a213617c00f85e78bd3e388a24fcc47beddb709b8edebac7fc99c76d081" },
                { "tr", "edad43d4a466492d6ef75ec190941565f02fa601bc590fa5d6603f3e8f1abff360d1e8adf267a9cfefaf0c3c1eb8429e53003f02c19cf0d50497d1aeae5449d5" },
                { "trs", "2e6d6317e506be4feca12648a595bb9dd0609453286cb37faf4f44ef9242bf4ea3fbc00b1f1a1f5aaeb94aad2a56c4e2a78eccb0d4fbb4bef7858625a0b447c7" },
                { "uk", "e85460beee678c0ff8d95d17d02c50d799b24ad43cff07be55546e1c2fa0126c79b9b6dda0b0559b95a72cc21bded4d4152172471daf86551fa78b41ced16ff7" },
                { "ur", "77015ea16b73e6c4c0f8516337d68bbb6972a66b1272c5254f98644198576b16fdaf66159c762b1ade29c53c48008957a33111ddde958fefee65b2efd4111727" },
                { "uz", "263e072e81e4ade6ce443703b00d93b0c3b83ecc042a0b725efd031fadef1ba3444ba98f512fc4149e833d9d2734bbbbdb36d2aecfea7b655b2bf233571d6820" },
                { "vi", "0ffceef5a503824ca653fa02d79393b4bafe498236179bf97720c88164fb05b6a3ef640c39472dd0da82eaf89b55239443027729115820d483dc956391d7780c" },
                { "xh", "f9f541bb1e2258b5a0b962d5f4e6c028977d4778330c4aa84f29a3e9f1c576e4253343d5cd366c9a29b5480d7c24373f7d6c50b7dc93d974661e9b81ff153218" },
                { "zh-CN", "22a0a2e337166fad932e18f11882f09ef69265cdd0b88c711c1edd0df49cb9f7a8c77c57e542a3f1609636e4107be9edf6d61ed1cd56596235652c779bcee9ca" },
                { "zh-TW", "2460066d81deef8cb0a9835abab47fc8db4e714873b31f16fa74b9502b0f2188b8a4f1720dcff9ae69519fdcb08a8ea441772df3df78bd7680f0f1f0fc9d892b" }
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
