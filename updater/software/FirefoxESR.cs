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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0b9618f140ed7eab8330675aaf46e2ab2771c297e7705859639f16beab756965c54dbb94bcc45cfa06a2df3600490ea45b167d150653bd1f9ed41eee52029826" },
                { "af", "5c7abd85a71f09f7d36b08a7881b0cddeb78d7435dff050160a54b6de36b4dc64c30efa8a3202ec8155f4326d326e011f26b06009721ad64724095f68e6f6d9c" },
                { "an", "285c5f16b36d722f64b01a5516f8cad12f30098546212e3a4726ef2e6c90d7aaec367b1e214c884ff292bc7df3ad9e2586d544199a34e576f5bb715a6e962005" },
                { "ar", "ce3a07230438e2cad893e04e26c5341957200049dd4ccdb877ea633b630207d8b41287703792c757f4d1ce2fbafb4e9cbb62ace6e7ae9e25838a2670b2658c5d" },
                { "ast", "6ddcfb311deb774a835d1a4ac6f749cf870199b69d15746f71dfa3249bca293eb44e130d508281c3eac9234450ba5982b2b528794b10f40c43c09fc0aad9ef82" },
                { "az", "8c57bcf079db307d56878d8c9d041bd54d59ee8781a00d9903f06d5be3218a3dd6cb49683f59dc1a783f2d91910921b2d814a7c1ad319155d65241f9132837cf" },
                { "be", "f9c3dee9c4275e0074eb56561adb62ff034326702f464e1cb3403c3364efffd4a030d463d448c32ba9fcf394810e4528580c4ec5c5a33114685b8195e85fe89d" },
                { "bg", "c7a17baa905a9d30f30180c85147abf57fa41697e7db8ff65b022913b31a87115304b7da1849105281069b08dc2dfdc43ee0e645a6267c7118d14a7f1f77b3a9" },
                { "bn", "20fc51e63f36883cfc360409717397b694b90e8d9395ebe2a7c22d05ee9ac5a21da89706e9bc9373fa0ae8f96265cd996ee239e359175502f2da8b2ede88955d" },
                { "br", "bafe1074d95b40b869178a4ee1557b8937eff61152b27dd91f23ff6022e546005bff186c96c67ab8fcdcabfc74ee3f624c8a5a5f9c4cf433df6ed792e6bea465" },
                { "bs", "f7e6bc8a57bc6e1a4ae6781fbdcedb58502623caf5dd59b00da781fcbb45eeaaaef81fc9e908de1a312266972a1343905c885d5d7d423968710e561ece4ee241" },
                { "ca", "729b78b94a1ca930e392f02d653752b1236af3af425331fb22e56f3bf137d2313b7f0621f7030980e49dfcf9591ef8a948e7ff9558cc26924a170c3bf82a988f" },
                { "cak", "17704879745a8612f884735e4be3589a98eaf2bff824e692a112819a627105d4ca5e325522b504ccc94cc392aefbf8d1a80401824b6a5e122f7fcab8ec456119" },
                { "cs", "b1070dcb41297a6afe7aaf864be5360c12a619d265ce54083e558d1c1febaa9353cf2e5f9d81c50137107c28154143ee8036bbd6d6c12f76c4655c65ad134e28" },
                { "cy", "701a51cd6d73a0d81fd0d275832ccc3e18bab32ea1b7675a91207f4271ba67e9a2642699a6c7e0af3f60d1c2d8162448564ed017c5f7953cc239333f95804a85" },
                { "da", "cfa50e9c6452f98de23e13a7c7c2ac12ae38fd0205cc7d654c564e2ffe723ee6ca955e7872227f2904ddf089c9a52a5382d9160853c5ca7c07b01f2f8c047476" },
                { "de", "f98b59482d61a749d72d50038e63409abb4fea6aeb9a7ce0fc80636fdc27d2493bfa58afd455f6123c7350a4f391d8ec80780327dbd4023c20948aff9bd4d71c" },
                { "dsb", "b5d4a56b1173ad8bb6e9595b4dc9309dd85075685f787b5e420578d8ef80efd0cb13da370576d5dc613c217b939393c8614bee3a319ddf0820d67077cd127ea3" },
                { "el", "bc8da7986bc11c02d2fb43527211f6fba54156c21e2c876a60eecb27af0c15c5af005aebd87cf8e491cdbe15ed84ad03feacfe0448b2f33e7472df0fcd5f0e46" },
                { "en-CA", "c987bdf13e077c849acbec1db181cf73cd74b6097362fa31932048309d5b3cae7dbf0abc43140d01e7d20cf89b283e6d42219a84696928618e6f5decfb977b2a" },
                { "en-GB", "3240caa86bbbf9321e61360057d07672a502a92be499856668c358d791936972306a6deb7cea13e5f5dfc2f3e2595eb1a783f358b6146c90f25e6e4603470527" },
                { "en-US", "aa550cdbe0287e9e5a5e879a4e0783520594aa34ccdee5cce9588bee56fb0e2d5d15d212425d01e61d0010e561cf9c41bf0d55a9feb1320f992705abe3fcb35c" },
                { "eo", "f922c0d958461feb2b5af2d006a5e16884d3d323afa08c3faa8db9cb7fa8301ee58ab41153a0af1c9a0dc5af13f57487bec6a2797462aa8534932bc079b7699a" },
                { "es-AR", "42d3b8b452e9565cb084dd4225f71faedc066fbfc59d34f819bde3d2e98dae26e02b50d08cfcec80d3426f17750a57cc9b3af45d9bfc0deee63f30abf96b50b9" },
                { "es-CL", "4504c4512f6c21b760a5dbd34dd4fdafb8d62666adc98fd7da3e69e0f395f89cdbfa27903ce9761b793df0e5703059658b61e13563185b4d18257d8ca463eff0" },
                { "es-ES", "b9c37ac592e60de5ab595234e20feeca0212d25a3d1f07ab65ed175e7f3a046750532a5e4e1662e89276e0d464e98fa15c66dd5bc9594dd8a729de54c3175cd0" },
                { "es-MX", "12a60ddd1576203d42aba4bda66ba928e9c1f2efba5d4574aca25e1c4722402f964b0c2d0f5a6f18330e211d8b5dbd7f1692cc74ca2c3201c3659097b15489bc" },
                { "et", "09ca88102c30ca02932b3805792ff85cb157b0a374fc220bd1add1569240884ca0f18c1fbe395ead621b6b4ecf96b0c0cd1ac2081c464dea7ec0097f4b0c6f9a" },
                { "eu", "313f2dd91fdc2450aff0a3e07258ab6d2499dd965b148a9614b02582a0656be9c13d68a7496b271098e98182e765bac259b6fa76c4d84fd296508e7408b2ac4a" },
                { "fa", "b9d858b3d9eed410a9f155a880323dce7e4c8e25574a20416a01e67a5a6f925f2e9c9425def1d1c9338717da9eb3e78a6b81058460f4dfefc2d2f6a6e000e434" },
                { "ff", "4e20b5478393d1795e0ee3d95300831e8a21c80ac1481ba5acbae438f414a84dd0cdfbf15fe81c970ef43128af5e0b43a2f55ff194d0d1ef748979148b843aa0" },
                { "fi", "7c7202091aff365afcd6215b6c3f26d5f07c76dcae0a9f6a9ed8d8c66939c7fcd04f906dc5b81fd9957f237c8abe2ae4f380bab68b2c6d6f1413d0e2a475dea7" },
                { "fr", "c2156024175c30b70d3a5adea617a3d25113d5b477cddec1718f50074f3546c86b61a3d467a253e5ec00f184ca2eda2c52cce02ae28158685e806f62d36abb30" },
                { "fy-NL", "fbf91ff15226970941430ecae2431c5b88a95742127aea7e0a51e383d92eef2c819c462cb3b74f0347f5bfefd669347856b473dcbb41839857fa0fac747e7acf" },
                { "ga-IE", "4cc425f1f4576102e1be37f38ae695212c396099b47cea8d5f33f3ab7fa204eb302711cdd06450f9488aeee9c3cf2299e55cf02c3e5355e26fa9a8bf0877d811" },
                { "gd", "56cb90de0e5a4a89ad17d73aea850194658bcb00ac1f5f165c708576fb9fba4c690fe5c451b8ffa0359c69e939ffc4b11eea0cf153a7dc259d5afab286130ef6" },
                { "gl", "93f5dfb4b4fd3f72c0ce1e994c537a8e1b0fb8164dc7a370e45f9798213902434512a05e9a0ae0955a9e6485dd184dc71684cb3163c9a5c2d701a01d7882ab2c" },
                { "gn", "9caf333922560c183e0eef27b318627f1661cf575ae93f310ffec99fb9653f57ca3b17a6e8798efe30863aeb62e667e29e0fdf6d9e2257b3da73828cc8881bc7" },
                { "gu-IN", "2140a7bdf5677da5b36e38b4e36f7ff59f668a9f4db7720bc0784cb28bdea12a29ea86ca0be19af8181423835ca8accc1d249f7d0427eab01334a42004ef8d88" },
                { "he", "f99ddcf54e2fdfcfc7f55a420759aa4555a355624e1357626786c8e923c109ff81b9cf99c9ba86b8a6547566618d2cfb576520e0ed630049fdaecbb63bff51fd" },
                { "hi-IN", "49e39df674f34e39a9c45570d87aef09cdc5d2b7a608d40c7b0f47f7118264a66cd749bebcf2f66748aad6124b59c790f9c88784b2250c56d03c2f45c8e11b17" },
                { "hr", "3febaed4b2e1d6ddfa12df833408d9bc2a1e1c237dacad4572f2b34f8958946fdf8b031e407eb8e030d9644378b6f9551e099a4b53980429434e16be51043a39" },
                { "hsb", "03ff2a72760a806a914d7bf5ffd1a2575d8db51b54da817845919d7dde9496acd224dcf2f9f6f425d69c9f11cb96a5ec389d854fc424a834a51466f7f1ede2f9" },
                { "hu", "3ec9d66779ed76f428c9ba4c1d3d7c47a65a2157418ae687f8ba1b06c11474d8361366b5429b4b6a78ddedaf840e050af1c54bc92726d85ed9b0a84d8d9a06bf" },
                { "hy-AM", "73d83845d151e317e18167f5f991eb263644169385b369e253ff6d245479e9b3c7dfcd39a32ee0a940d36cabbb943f904e98f763703355b14fdcb7332e4099f5" },
                { "ia", "a21bd6eb9e35c4b7dfa85ebe353257c25ad4396500108dbf8f4e5d6aef62d999b7953e0dfe4c6b9ebc83999b53d331363eaa095dc70eb01dd1dba21037132ee7" },
                { "id", "175b547917f5b0ff5e4ac49a491327c813fe72c1cbaab0aba6e80d8927eed16c283e7aeb1f58b27c1997e22dc257161a58803b713b1bec5c352db482facfffe2" },
                { "is", "9b44d4e5286d57b34c76dcf8246563501539ab6592b65e24958fe65ef75b87ce4c80105571709bb7f43a724b8959802f6741b290a7578f11275995d328f13b9b" },
                { "it", "455d290f39a2ba7f5537987577f2193dff6ba488ee90bffb6f4390e2aec4c9a25027b6c11ae577a9f0cbb66efbd5501e578ea945873157b09c95ed495f12aaab" },
                { "ja", "1a34c4cf0d4845745004e3f95b52ec2c77a14b81f85d7ff29b683d487745a440e427fd633161290423cac02a08d384cf69dc82e14421316cf62209a17459605e" },
                { "ka", "aeaf67d7066e9b29daf3dd8fbf5b1c3f622329defb02a243fda7e3899cdfa02e17f088730e26e09860c26ef2a56a07d300172f8cb5b8da1ad5db3b4216ffca39" },
                { "kab", "ccd853115c1e9f675022ed7495fe1ee34287f1c98e22a12e7400d898635c16966c24f56be800718fcfdc8bcc3848d7dc88e668e1cf6f9500ff7b08db8f8d71f8" },
                { "kk", "1a9245d425e853b07d623fc96d9dfaf06ccb6ef6dc6079b3dc133494a7db3950ccf384727fe26cd7bdaa79326f9f2240408564d8e95160d2f1dc845435aced5d" },
                { "km", "42993e469f256b1fcfa3e7d236f5bbfef109a384600c8c865c404eb2c1546a2c1de0b80b194d1a9f17ce9000ffa8ef44d79748771436abc604c97dbc66740058" },
                { "kn", "4e2754e44958145c64119954b23b018d7ce5b71574837396dda9bf2c6790ec697c367425480b5f320647f96f6790b1cb7ee31032d9670d138c678a82835049a3" },
                { "ko", "610ed8bcb9aa4ac02c99c117abef73bcf50e68238919c0e8f8b2f7631fb992362fdb36366720604557d130244e9fee89e506983f047788214dc7b08d8649d3a8" },
                { "lij", "4462e1c539032606df6011ad1516ebcc7b970a9633041d113d138f7bcda6aa4b8347afeec61513a8cd5bc05fdd5ff9a0c6a694276443ab1a147c21a28f1c8e42" },
                { "lt", "1e5e5e1a3dc27da3352ceb4ee962890e49335f8086f2047f92e8e7b7fe877cd8c71f4e76e5e09a6e7af9447e66373417ed3c6ab714be3a787bf4b0416dc386e3" },
                { "lv", "47ef395693342e3ab46e7ed7e548bb8c3bc95b3e5b1e122560e0815e148aaca53f08c6ec35b6c67c0fec05fd68b11cb3fa1f0f5dbca32b78fc8e7ee9a4c8aec1" },
                { "mk", "b66f354be041c9f478c9d86361b1e6636dcba333906d84894064591a870d5f929e3d1aeb248188affa54357ced749f2825a01aaf6b26ad0cd270cfcf5bfa6636" },
                { "mr", "d717451d5c526c94d7a6b049f56609e914f4378dfd3d90061c517f2aa178319a3248df5d6b500d1d549b588738e6da830d3a3a7f3a6dafa0fa09cfb92f546f89" },
                { "ms", "b4387bf3e7ef89d60ce7e225abf18fe704afeecc9172fb04f6d2da7338e153a1f62eba823ed28b02d5da4809793839cf4ac7ed5449a3ad8516587137bf3c7931" },
                { "my", "e84fba1f8c3073ae5503ce98984623b4808f78b09e8156d69d269e6480475a430c714f7e2d4a00278f671727baa9b847d4b4594fd7b520685a4b2a1d239e580e" },
                { "nb-NO", "748a7f38a5a7d18cb8387639dc58951433517e7373bb75fcc08adbb755899e9e20d7c1279a1518a160913ebf7ab7163169d5eb2ca589ddb19d34217979773d24" },
                { "ne-NP", "4d60751eb68a92b2683372d54f7068f2986e808e22dc828ce1a3db446161fe62806ce6439b03149fa464a70c2a4dfac4c3b61af6b8dd4face1ba3c5bc9ba8c4b" },
                { "nl", "4f6e635bd52e18db0f97d127e174933901a3d35aa194f43634cf6fb8fbb52079a4fc2a2c8bc452f2a2b3d4ef26d8dd4ff704d36a370ecdd4e7c06aef0ecc750e" },
                { "nn-NO", "34a3f844bfa71c2c6c55830ce198e760cf9b44a1b114e27793f514b918faef9e5e877312ef39ac31430e76d05a40143c4c3a7e2890b2afeb6842053c2870152e" },
                { "oc", "1954b61476167f2c49ba79f0e5d103699c18be5542ccb10f8acecee665d954f888644f3992264b99ebfcc7c476b00a9f189cc43de94cbf366260245b98786b04" },
                { "pa-IN", "6ff9877f8298d8780a97943bc4dad848fcf05c90120b793bfe4ff390ff3c709c4917cee9b0442ffbaf9317136f3b02d67ed9dea70baab47ee6feb282b188cf52" },
                { "pl", "152e3cc55d28659db36e0a31f4a3cc5bffbc90df577cea5ab33dd80c42eb0dbedbc84849b2b9075d266306285881ab03ee88cd953f5e90b9b16f4fc908059702" },
                { "pt-BR", "b4e26c8a222dc2775d1ee22880a3cd24b741e556f2554022eb73bd5aadb2802d364fa45fbde8d23c7c2abb6e3ef73ca7897566dcf0d03b26f5466a44a7305336" },
                { "pt-PT", "ec5ca52cc7027e01ad1d182ebb134e6e590ff01171545e52ca471c6aedb4f45f85e5f31f4ebf0546006a9bc7f17f6bfc2a86c6a897cbb0ca17316af36d03f5df" },
                { "rm", "0663f6aa0c7c4786c3863d48bcff6ab376358700f24df4daf873e069163f48ec758a17348f039ba74d9e378c2ad92281220894c3935b80e0bf311c9b68d0e8c4" },
                { "ro", "ce80b61a95691e2ff3ba4a93295148eee10127986172ca928a3e352ff209a183c03eed10d8ccfcdf547e40bcdefd9557f35796ccb7c67314ad336e8c4ad42277" },
                { "ru", "5598243ff986c452c4b5617db90cff6c45c071c0a01469ab37697fab049f2a2915675b25cf2707fafe660042e2bc903def88837ad8d452f24ee8328bf781a66c" },
                { "sco", "25394111a223de17ee85f11f67077c55a0128c02f8d79add1ab505561944642e494d6d5588389da7f0e87588326d7581e7c983abaed35a4913d4c2c2d60d6918" },
                { "si", "49b0881684954cd05f2e288e3249c34c8725d46a3719ba9b74f8de4725a954a4972caf5c67df93fc0deb41d639cc721794c52445874184f354441d8b39d33a04" },
                { "sk", "0b1d7804269d05d8ecbff51deb3669206694522cf4f1b69ea5ad432945ad0d77c8792ba27e3e8823740cba6fcb4e84306dc2fff71e46f0ad2ffb3e4f6fac6e8c" },
                { "sl", "0154a4a86b781a33c5a20f2e758d6e80365fb847da01fcbc64e031997ab9d3f6e47c3bfdda534d5cc7d0cb1e81cd42416971d9a8bc59df4723a02269ed953dcf" },
                { "son", "f008d36079b6ab4d76247e547a9f99423877f2ad42b20586c0fef5457a47e400c0cec555229fcf6844ee5c305aed5ff7a28a73eaa35edadceeb769ff94c22e40" },
                { "sq", "a532b24e9ec4395f21073dad0006d003b1902c4b343459f04b37d3e0cb9279f7f920e4d23eef123fb1dde53994d279804c009e24dcd44d874a69ad41936f4e46" },
                { "sr", "3dfc347044846382af83ddb3e33ad926e270259e6e5f33de56544ad9d655ea8e782ea1f65802955ae8b83d63bc4aa69fbbeba884e40cd041714064d0b678b2c4" },
                { "sv-SE", "80b23cd49cf00061f8bab7471e0ebd09bcda9e62068b0b4a1152f47243712b16a7c709ca723252a406dc860cee0a5fffcf39c45931d13d46c67174514d344d25" },
                { "szl", "e3911748d93a5f7c88794f2bfca2305a169a43b82c84c4b918ee077fa94c683f00fc7dae6a6bfaba7fe95644c69cac23c3c62542681c88fdb860d5d6cf375bc8" },
                { "ta", "da7ab2850af5fd7cf5f6515d0d214f04efd3f3af7cf01708f05bdf1813f996fd631d9b24060b2055020cd4e651f57f88c2d37ab2d64847feb9a11df664084892" },
                { "te", "8e2bbf2f942a218b93c3deefacbadc08e2febb3e7cbaaa8dcc7b2cda5bad7bea16595ec148f259b3091da20a6fa4768ba7758fdb203a8effe2fa51e3986000f4" },
                { "th", "e7cb2e1126854904f84dea6bb605ec1e301a855d84c1eeb5d9a54f7b556d7164e3f69a8fd38f66a2642ba6c4b5d8029244110db66ca424ba4059eb391544fb59" },
                { "tl", "bbc909e07a2153c58010551de41ab86757a69e4d464f811651be15b10f9ddd2aa02a41677573083b69517178576fe6dd7423f8dbda92f32670f370e921b6de0e" },
                { "tr", "14502e948686ba862239c5ec3e523d6c3283a5b4e8df708df405607dca80407d220272bee9b274b8b064864c467110d994e8346b331c086b3f3451a6cd973150" },
                { "trs", "da06bdb4b0fff0bd78bd99169bc07fc4198e6e6cf98388c5179e47ce1ddec91c2193cc3f09464b5f603e57b9233d5f987912fad78fd7dcf89a1f7388aab7075f" },
                { "uk", "2dbc33ded5f7da7631dd04e11c1ee1f1f302d9cab0f48cef7a738ab2106255fbf4786df79cb743a459b058c861b638508d67f11768ce643bcd0b589cd5a8f291" },
                { "ur", "b2686540877e625ce86d31e9fe92a80bfe442194947b63e34a53df8dc9829af8c9d5e632ac9b3574cd5167e9f253351ecab0d0f6662a2a1300226a70eb7c8390" },
                { "uz", "0f5df94e78ce2fb0829ce4fd850d1583b0e66bfb6b46517d95e2ca8f094d430e95b6f0393c98273af301cffdfa09f0ba37e4a9ab218b3c76b3cd86be90093e7b" },
                { "vi", "05a3beb937f8fa4fec7abe58823ee08bda8360a079f2357d9d708331563ba4c709448aeb2e913277f82aab28d33354003d98faf039798416b6af08a9c61e7869" },
                { "xh", "4e9e7fd08488f59ac3d51738fae0a6abc80112a2d7b10e461f5fd1aff3103f6415572e40ba087b67aa23059f004adf8b0d12501c87f36e08cc0069ba6cf3dab2" },
                { "zh-CN", "550f6a5d9da6e548ffcb487cdbb72369fd961991510c5db22a0cec18a26f8a15a3b5b79a4f09e5dc839929e9eb2d1a25e21003f76cc8e057bde2023fb71bdb06" },
                { "zh-TW", "6561ddc762eb2ac4b4a3d1e25aace81404147511c2f5fc7976d466777fe14c751d3313670a18e49a4876713fb636687822c6dd21f737fdddd59a6008aeb53e2f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "c32b50d8138723ed862ab7b31d2e453f0464341e61899f03ea02d77637043aea04cff5a5c1245cc2f8c0553d112b522ae774ceb8db92cabae327b110fa175c6b" },
                { "af", "5d8b038b2825e45b9e6c1c1eba1c707bcdc6bcf5947acff0ea4a36b245eb404789fe86de40580aaa5b4b1c6a2156fa843e699507d66e5c81112f8a2516bdedbd" },
                { "an", "6e7c7dc56478067c0048dcc5832a81c020009c794362d4bc90aaf8111020eb1f7048ac8633e9adf0fbfca6f9cb10a1629ae80fc841a8a6a6c1b847afe0131b28" },
                { "ar", "0f8d029c76fbec6cd52f8469e8861a41af7dd42da41e599ea79e764418db58b951166a448c74f3edd8b2ab8eb2148162256d88e42ecf16b22ac3d990e1cf5e73" },
                { "ast", "fdcb85571033b80fd0053f59ffefd2180612d26297d9d1743cec8049154ead24313056ae43b2f5e3fd75a55011e4c385ac93e692da395f2f48f8e6a7ee8ec851" },
                { "az", "9ce2d5a7d33277791278f4f97b7cde17d739cd31cbb5b9d967b6f81727e571a443b6e5a4fd4563045dd3555e1f4c1dd1cb7b9bf141daebdad59976bab0d34a03" },
                { "be", "264aed39b7979256473173cf89264e9576867ec1713678805bdbeace949c60103a1ea95c3a6fb137577d293fc3f059ba6bf6d8c3aa9b6224c1d4d63fe05e4491" },
                { "bg", "968f9602616df4c653d9a518a223ea8745c1858dd6ae86573f4b4c9ba932f423ae3517e125ea3a9931e6ad16ae934bc930ee6e1ca996925676313f5337853643" },
                { "bn", "0ec086432500a8ef3f33600eca0868111f237aefd829f26db9156801332a16ee04892b495d185dc8e1825d944bf46a1149524b7df57c5fe0fe027d2fbe036744" },
                { "br", "040592399f101f7a96e9d6d7a3d6295b8982d22a1b03433212b43592e60fa2bbdc56bac62360a4edf1e4486cdfdb7e40782b966c2de7f6728a3b052179756e63" },
                { "bs", "f03edcaf8e3471bfb364c0bbd1693307e2e445788f20addc7a8f37cc55cc7333cd786855aa71adc1c0606d0db5d6eb2d27696a8dbeff99c155a2deb464490d8f" },
                { "ca", "76e8463e4751747d7c036d892c68e6de671e319f4f9eeeaec17a945893c241416047110d9f20598d38904a1ada6286efea333a8898847fb3f3e8a027cd28d99c" },
                { "cak", "9940c3f1d909199aaa24208281b315d605aedce053f2e65ce7ddc8bfb6bb6d340c75a8d168dc6804466faca22913bf408442433f6954d4df4ed1bbb9a1843deb" },
                { "cs", "16965fcdde973469e16e83b9c2330f05030fde8a6740bf8ec1c1388bba68bc22beba1c2c9bc41e4b93f5e4d4390860c5ddfe5a07ee19273e0e1645237a48508f" },
                { "cy", "1855cd8751f656b59ba13de365319f0cd5e683267a1a44400ed1e0c9ca29ef052f7ae4861b0e7d17d6171e037c868adccc270c1e70ceabdc6f391cfeb82d3532" },
                { "da", "839b0c1c37745fec39cd88229215a8f1c36bfc8951f1088c670d17c40cd627374236b63dff590081018a327ffc80feeb18966aa44a725021710b4ffeb15696a2" },
                { "de", "5ac2acf62ab4f40c655add3cd9057d1265c940c91ed1236006095a3e55949459ada037457e8e21276d1d6a24771d379efd324be8198d6b8218cdc78d35297baf" },
                { "dsb", "1f307768d5c2f5256e54e134992e3a952386b96ae5e15fdee416451f2f09ec4b29f413108a268773897f4db056802bc4a66ddb683973993e088f3f906d4642e2" },
                { "el", "a3b2c3bf850c8808a079680c9b98be214a7526b3871390524d3c687723f3502c4cd02520184f9f374342e997fa99df77516fe962ae4563d5927bc81a9dd8c771" },
                { "en-CA", "ed2f68363e5d0a1cbcc465a05d10ceb189b50970de067d9e5520dced95a893750b2fec5638be44c8ad3b429f1e7d873d5442f310b7ae6fe8550b4497f78fef5f" },
                { "en-GB", "3cd902fc0818cdb2d0ebd876891526a108fc560d6efa02b4a3b0f8de2b568939180059c9b1d3e95fbf51f6846f0e95125f173e1c799e5a21db51f67ee376b436" },
                { "en-US", "8d5c880d4e382542150f37a1f0b045dc8140e6a7a73afdae0a9605c26f7fb19aa9e7311cced6031bcb564d8eba0d7a8b08362580fe4b0e50571b62a31ede4be6" },
                { "eo", "2bb4401b97e16b5848e7fe019b28241c1802be5f1a6c6f43d4280f89ebf3c1d208241ec8fb51197504b095bf5c7bfed7478fbea1cfc26ab08a79fb8618918815" },
                { "es-AR", "d56a780fb96de97506ec6155b90a0f002febd1e8eb9d892f3e6280a8fbb8184301c700b6ed158ce277838919b9095029ca8f7a3a71db4c19c1862c31ee2dcf37" },
                { "es-CL", "4309c0dca836dc2cc272c5df3a3361d70a4b572dc6ca0e34d606397f85b6eec4805d77a1acca13acfbe97bddf3d79311633b9faa8f07530b16ba95b00f1899a2" },
                { "es-ES", "6ce365cd5900fd87fd1fa99264fd63b5e3ba35051193fd7f9abe5b4a4ff73f98f7f819642ed02fc994c18648dc3d2e3e8adf780f7ecd01fdafb1470b1f159ea4" },
                { "es-MX", "299f59a8d11e74e782d13a9b6d128b991317aa404e127f91e024a914ebb266c63401dbbada362b23aaa939804c39b92ea08dea1b0378c5baea1702fae4936a72" },
                { "et", "f53c53c7780e558ae103cc8ae7a128f0d146812d9f1191b8ba57fe93f9d9cd17b9fc142126ca694ebd6bfa1a2ea65fe5fa452706711d5f938c8db94ac176db3b" },
                { "eu", "db5eb9a146e20e812631c79e36d5d4076273f32081a61dde824ff74a6878da2991647516761e92540a51627d0f0efdaa33fb70b2251c41a425a90f1da09c57bc" },
                { "fa", "1edeb4c32ebd9c8f40819291ce6e56051324b6d131096b336a53e9647df808ab323ef95cdb9f9d9a0f93408394e08b80e43c2144bee2b0361a5c6a30fa233cb5" },
                { "ff", "6a4d70a2369f70b2d18d14280883c515dc636bfb91866e02a6be02617d4a0ce5c194f29270205633effa9fc96729da09f5c567889a0b0fc1a8911d800bbdd98e" },
                { "fi", "08b3feb110b92c39af1634a32b4a95c4d39f8d01098b76f5a92d4d2e42be94590ac8dff4eb5b057e5a9af1797f1135738701186ac3e6fa158eb0e260275faeb4" },
                { "fr", "462d3f4a2f6353a0fc73015199a7a0b6a4e2635caa5922520c4185088073325ee0c2a8c26fae7a69ceefddf12a9e6df7073b928a14e8e8f732300341f1eb1bf1" },
                { "fy-NL", "2926f69632e60c33ac96d20fe8a5a0b3f153fa7e82c84db96829e58dd083991e93dd64e656a9ce36260ba2ced8caeb23862c88f7f97b3f46596fd55076c1b5f4" },
                { "ga-IE", "d7a8eb4616472edd798879624c8f829ee203428c9e30bc0f31b2f48fa5173b612f35bcd0c95ed12702c0a9e301a60a120d3c2621b1595922cca60c159738461e" },
                { "gd", "700e04891d1d0dbc5f4da6636797a8a17c921182037105891697b6c781252491cc4b77da250329b229689ed4f48e07876cc2f836e614d4911f83902d922b9b21" },
                { "gl", "696868bd9447cf3db57f4dbaad6155eb8c39d60810d3c74291bdacabec1d25aa880676617ac505f44e56fd4f6f4ef14cb5259ed61dc85a5abdcc4d2fa325ea20" },
                { "gn", "2256e2e752a644c0ec6f21961747e7e402ff0786e0e8a60352627d76e0efec280b753abdcb823532237a2436049e94fa5287f673041fd16b0fe9631492965e8a" },
                { "gu-IN", "fb11a46bde02bb1d9d77cd382913e7007b7c8c9445a6fdb2f9ec39fb7f81991300de1df6ba30552ead8e7be750d1dc8063caba40744823c041e23e0665f2ad29" },
                { "he", "dc323794436f157daeeb71ff4f3d9ebc2996ae762184c12ec885cc57fbf16fbe425951a65823490bb9c65bdfaa6c5288efd910430b8f2174859c7f823abc1fde" },
                { "hi-IN", "d8ab4688ea423300ea21a78495028afe2d6924c7ff98cb11581c814ff2f649d365e84d3fa1c8ac04f977e58754c678d1e4733e4204b74d1216bd35bb6a38d39b" },
                { "hr", "9229b53808764a35dbe63ba6eff09bf82d3264477246970886204934dda26e6bf0058e226528c02d4357f9441d0fe492e55f823221fcf7eeb5501262a024b424" },
                { "hsb", "0d24b5adf85c82b27557a342f7908ad17c3462ae534731a9f5eb43b3b09a93f0b3213b6792ba5a9cedd2f1a8999c4e4fd0cc91ca2b96cf03d9a2f06dfb705898" },
                { "hu", "e4d92ecdf40d44fcd96020a5477f1607b5aa01983b370a20e1180dc3e5eb0b8765f0465b7a1d251402ba539a71db8a7d5105c67081b700fd0efca84a456472fe" },
                { "hy-AM", "96444911febae83f7d9cfe551de2db662d5bdd05d489d270e5cf369d5f8709569a3d589c52dc493bd492cbb28f72df27fc80bcf712d44064c7142521b50f0f98" },
                { "ia", "77c230148f047c03b362f67f70b3d2ad2848bcbcdc5823baabcb3b41dd3d61b0aea90e53c00ffeaf95459f4672a4a0d7a454e70a9c30a8ab8772ae714fe224a8" },
                { "id", "34779a83fc19d295c998c7b59a6bceab1b0e4d8936dadd20319d78a5c8648f352e7d705b5b47d9d94d4817903368418f77878a58ed5c87ce2ea27592b9cca8f6" },
                { "is", "33e6c87bd194b35d73c92e39178fc60d5ff1b1aa6d6a1e9e915b177f07ab63a5220f4053bbb73587b07c8c86be504bf8eb3888f4b233a150f2da8e77d4984e45" },
                { "it", "df2554795e3952ae4809ac203ecc5255ebcd30aa622f04835a471ed65bd146cc1ea5230108a8c7a893e0cdb94dd1955f8540481cb260f3c0dca2aeaa27b85fae" },
                { "ja", "bee975a553e27cddde2771574fc65f7eecaa0f216bf4d7af3ec72b5f0d8e29768162e93038fcc66b2c8f25a251d1e4aa9358d02dbae30b969812bc0cb79fcfde" },
                { "ka", "2b567677ab70c33dbba1d654f02f03de674e09e3bb657e66c04d7efe926d9d3f79d0897a199b910de38f1f85f720d546905bbb5d42d3cc6d2ee454a14ac89fe7" },
                { "kab", "8b91e1d25f648cbd90af06bc2b1f1ab9a709b18c245053b8c660f917519ca24b54c3eee393a6a8f4879b63466a6eea329114d7cd2365fe8747c25df56c456c17" },
                { "kk", "de5242abed95b250f6021f590a9d18ef84a8002d01aa8626f49685186e1b9cd298748816d4034d4e41cc5f1110f1c1c118e43560ab696f9cb2ae7b90ed38ad3e" },
                { "km", "99a6b24adb14f971f1dcfd16a810048de7542afe3e85c5080af76fd31a0cdbf39e4d75f42750283fd462b7ecb43d1cee7ea68643101c6211d2c4b1a566540b78" },
                { "kn", "1a815e47225ce9c5333be5cd6af55967570658e658b29994dd8499dbb99937ccea938504b0177e4df97c361241c140242e7875541a549038944f6e7496526f90" },
                { "ko", "a1158dace54acad3bc6776211e877a07d918daa29f92d362ba8ef2e5c25295592aa97e82a42b861deff39971a3c972348527f5c6aa47f321345c9b9db9674969" },
                { "lij", "9e8fcea748e7aa56a128b4e1eb43b9f0b81b643bc11682b4a39495c5aeb6cc24c109edae74ea95c75e694c84b8c2d72abe29da42d59af8ebe917ef0ec92459b8" },
                { "lt", "cba0b43ffc5ba5eabd4e911614b2084f274cee8731280477e5b7b383095f91cf39173c64821f6a4ed52d5bc00ae725bb3949c5f65030225c7622d15bac93eb98" },
                { "lv", "cd182ec6e02846fcdedd028dd3c1963c7aba3169909d5d8251cb89440dda4f163aad311c02e02f6609647e263516f284ae123d6ee41fbce8b6a44cbe841be9f3" },
                { "mk", "6ca278943d3dce1161f0e0fed8a96d4a2f058bae55ce113bfba0076c39b71da29709da23c1d555007c4692fe9da943f2ebe4f6273e01428c0463ae8134e58ac4" },
                { "mr", "40aff9c6fe0733b69c2d4e6be768b0fe9ae984ccd409cd3f55e6874e304552d33dda1b6a4f9bd5a04289fefcb77976530a23850b02302e5ad0cc19cd2b28376c" },
                { "ms", "1e99a9e1e3da0076460b8f2d478508f2ce22ce6168e4c59fe8f5fc63fd2c870449d512261281fa32fc3156c3b4588773d56750c6e7f949146ddedb2a185eb7e1" },
                { "my", "e5a32d5e4a8bcddded1521d4593aadd788be4497932857d72b3d00973d4651b5a573cce24745c0691fd2219fb6f7ff055fe97ea717e4be3840905fb0a99718c8" },
                { "nb-NO", "03f54ff3314053f31cdc2f1b343b0873a7f71cbf3997c9db394d60c9ab882e92a0d60e05ac9df0feb162df2622d8f34e16f75f20ad82bf504fe0a4ca6d2210c0" },
                { "ne-NP", "a5521faae859e65e52080134faa885738025fa1c277e7bd2c026d6edaba680a3e7ed014098cd0d46a3d3c9e4f6dae86c04ef06e109ecb7423163f4411f2f4617" },
                { "nl", "95bfe4c2639342e5ce7afa66cffc2d13de228f2790f3372a002576b7c8577bf0daa89d5f3161e556c270cb034aaf83b97a5e34d7ef1e4714982a63a4b486afcc" },
                { "nn-NO", "fbf75bf78ea23e316e58eade9faa8815f84651d8c447bf74d0e7d5f1b4d547a63be861938aa13b0d0540bfe1e5f29d8006acc18cad33307957dd2c450cb33cb2" },
                { "oc", "57c159c411ce386c4f6374b477b8ae718c241a252d195476c3d433efd5bea1fed86aad1816753a7ddfb2a2523baf2bb5cbe5c4b13ca49278da81aaa0b67c2481" },
                { "pa-IN", "5a30c7b8a40fd71981fbae25d603651719019a5d10481e9fd56439b4a954e7d76611731b2600fb5cd5529eeed266194a9725087ef747e5a9a19762ab5cf82a63" },
                { "pl", "e3115505738fe94f76800aeb558307c296526c725b34edf7b7cb20f286e6b48c9a34b9e0b329e4f62a699e49c69c5266c15da64de35dad31f50ea2c6f9e8e227" },
                { "pt-BR", "d62725aacf4b5837bf825304468ce5b5937bc01d24ac2b80f306ad2f511d37a790dd806b62483182861540c44043216a174b6ffbfdf2f31d96989ccdc89bd7b3" },
                { "pt-PT", "83323b1d2bb9266a5641734e9dc36a9575a7c89c70c6a647674b5a47ee6f615e9583e792d25d549ec7fee6e2ed8a16ef982a1c3601d540917f19d0087e2b5993" },
                { "rm", "cc8c5653fb50a00bbb13880ee91c3c11efd7e6c78bbd3a4acc94f72fe327874243630d0fb15b3a0bb8959f7dee150d3b99cb0077ed021fa9fa9cdd486a53c1b9" },
                { "ro", "b9a222b3c5c588d90e1cf6cf012934d2cdefce0444d3bc384ec150c448d1ac0f3410ea0ba30415a2e94f7ea3ca2e50bc8a70fa2e791455ec7f35390fc449d72e" },
                { "ru", "a9f9c3e6590157bd293b14d669e2cbc1a0fda96921fdb67a64cf06e552db403e2165f3e11cc0097382d23f82ede12115d7dd8f7c8040fbcb73983271b3f965af" },
                { "sco", "62f0eb2951f152211e2a4013f48f2acd265d7de6eebd7cf7eb5117d6ae8165e2beb52c8b9dd28edcb74c5d49fd62df6f48ea435fd779164fc8dbe84d06540f38" },
                { "si", "8be47285eaba7c91b4ac46556ed23f204cbf858cd0174a8e1695a26184514fa1119d2e4b825fd5220e284deee4fdee268262257819271d9c4f65f92ca975eff8" },
                { "sk", "83cb9fc5e576479b875d4128e9f61ab04d29cdbbdf5a3e273df764838b25f592631aa8a9855863ddc3177fcee3d72321cb10dc18ea2108f7ac331a2b117748d3" },
                { "sl", "556470be32d5c42603810d3ad549514e81b02eb7d66fea43f14e22315551ea728b6738666c834839b4603bf31ff39c0945718018bf17cdda179af613e0c60e63" },
                { "son", "533d3f48aeaadb2c86e4861e27170040eff54dbe606c107dd84aa9f02f8b528e1a97150e434aaf01143de666b5be130a95595ea8bd1af8a90b4661aa3f909f46" },
                { "sq", "19615de2511a3cbcba73f87ed2879f3d43c2b29a64a7498245ae0b24bf5d8df0f2dd4aebbdf99c1c98e2563530318e3e9e09f3613f908ece034c9b5ce3abcb2e" },
                { "sr", "e8613561368cf586206f7361dbfbab8928892fdb3dcea30183337d2583e9018b272cc1b64a19229aa1a68f39bdab3a4180c771791dd386975954eb1a5e440b18" },
                { "sv-SE", "b393014e3bdae87010c837fabf605b4305bf1b392c545fddf823742b3401b5a550711ef7e83fb1a8e6d33cf36173d46031e1f3b5233d38fe38ee4e93f726f79d" },
                { "szl", "acc12af6228dd93930f8cda0a4696a2016e5f89da747f66ffa0a3afa570555237579bcacc226d107b8b9bd00a890409f1ca137e2ab9ad4e7618a0b3d774a9906" },
                { "ta", "53de49d5798654915faed89d73931fa431a3b8e6d46ed03403c77c37412c49d527b3135561963da90bbb512f94ee90b7de0fbe0e2d6956b8f0b9fd198c9915f1" },
                { "te", "40af432dfd4a32d2e26d4771bfddb39f9c51d0d4cf2785612efcac6842d02ad7dd196c2dd149fc469b600a1499a0bbefba03a4a7016da5f417c2eee08ecb7a2a" },
                { "th", "7a6ebb1310661481cceb13ac0d204d06775cdc8e7c0792aeb102475131ccf762b47c5596da1f8bc8e24033115a642f6a6700deeb640ce9f79653e03ee2f4bd8c" },
                { "tl", "beb074672664ad7e9baa39c91ca87f0246663d031298397cd6fdee88cad2ce3f43775f9dff5c0416d42dd9964199387b2a873112e257d31ee08126aaf950c285" },
                { "tr", "2c72335b80c2cc940128a3b756467397127f6440c711caaafb0281b87639adddee11d35048cb67b19eef51960ee12368be755b8385c4f4b827a160dbee565c3e" },
                { "trs", "9101b859cb9511ae5f285c97a54dcbf2fe4bca56a8075f9eb297835297511c37411cc13d88d1b3302aaafe44ec857e72df00951e2cbf213a0cb5a3f84dd9e0f3" },
                { "uk", "474c4136a3ec59e361646bc07373e8f95dd3e37a4772f7b9f686cd4ca480578d99082e70ac2f01b93ad1496c868dd23b69fdf339afd00575c9a26c175d3bad2d" },
                { "ur", "98b83f64278f13ce4ae173f7cca60bc908282c61fe4d00953d0b90afd4e44236e20f6752764674dff815ffe6fa091f9eb18dffbfb68056cf4263d4e5639f6890" },
                { "uz", "4cae3094100d78693cd22c2e8e643f125bdd50bf527e9ec69cc5e5694043f643dbbfc764825846df4ce2eae6a80e39aa447d7895e8f764a51c45b73212aa3f8e" },
                { "vi", "f869b25b7d19dba2a1306068d58ec62854d7e15cbf87735d781be3f80ef2af81f9ea18efe8fa45904acfcf369a230eb29ece1af154ca6e31cc60028a2ff102ea" },
                { "xh", "fff975efacfe41f0f52940ec95faea61aeb5c3b692d2f3f1c7cec7f60bfe0cfd537d6a425c0367c3486299fc378c6f7aa8aaa6bf238690ebb2bedb23cf47af77" },
                { "zh-CN", "c926e6ce1eae6443fddb24a64e8bf7d964a202480232ca5726d88344888f9ab2464f41c28ab183191e0ef41fd2ce97873c539b21f3866f8452d8a9ebd5d6b340" },
                { "zh-TW", "82c6774c09053069417597fa671c6474ad9b7b96d293319e207c648132bfd433deafe58ed2e319f71dc21c2b558c7711b51df52170a130466f503c11889b345e" }
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
            const string knownVersion = "102.9.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            return new List<string>();
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
