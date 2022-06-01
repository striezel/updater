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
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.10.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "f5c81e108fb2b0f8c460724e683d71b6a6138f30fe983b6087782499d190c5ef6f51cb55e0d7369438a65aaaac4013386e64c094219292f00d75d35b2640f8a8" },
                { "ar", "4beb0bcb50ec6b2d4efb0abd0d25329b36896fe6d3031eca0451600d93258566f4d3ecca6f3a08d04ab0d13c2c642ecb774d8bd6ebf128bff063f5f9bc2bb635" },
                { "ast", "b074b9ccdf9bc2c1db2347840ebe6847753ee9eece327562e32e6d2cd885d5f056e98ba2ef255b7a4d3033bbf5f55a54a88009ec19de48333d04e160efd5f79f" },
                { "be", "82527d5d572eab54575643daddff51bd7aa153933dc3d0fb6572ab1ca5ebe01ccb67d2b86071d0188b5584678f54bad3d005df24dd78379174ebe7a6d131eb70" },
                { "bg", "41a2f5099bbe68e0d300bb9b54f3d04a5e5bf5d47feca8411bd4966ac26d0c22623b11a16e079b7c6cd9046c9c4ad31829224ee6c72eb0e64029aeba4bbd0854" },
                { "br", "b8cfd1d460d3a1d7ae5e3754ca20587bab41ce1e407028fa6478ddf2fb6e9c7785dadcb8da42c6852feb64122487cffbc074a7c203a176962d5f8e4be0b10721" },
                { "ca", "6e01e749e741b9513f6590f21b9a6a2a220cbfc6b5389960e7f939e6b6cbcbb36ac264148d5d78cea945c22f91ea09d242f0265ec765ecbc9f0a5a9be3134245" },
                { "cak", "fc269b6c79b1073dcef0894a5c19a8a92521aaa114e52103e9440f704edd5e24b6721aaf60af953b183762b23b05983076fd2cbf7c81966a14d1e5f4581d5d16" },
                { "cs", "76007a37404982cb9b25c44e765befb868887a820e7428c3b8f15945b23ebeee9aac1cff68e6f4ddb50f95c605d58785476a5cb70653e7bec1423e720b8622ba" },
                { "cy", "a23b9363674e3c33099b92473e70c85c7c44f0d4a53027759efde03ce988a3da2384127fdc9595ab0a703e3c8c624de4ddef6b8a87836682e07a6d53394c12c2" },
                { "da", "f655949fd9823d64c6e2e8b218bbc2fb8294feb9c97e93ed897dd7e0d9a980db35045d05324e5af6df58989834c1eced8bd736741f943c9bf831e79cfc15c175" },
                { "de", "33b261a267bea110c3eb70faa299ae28e9794ed2c6a34732861eb5cc4398fea1129f94d2cd772051ff040d177015aff440e0577cb333d47a4216b43e666032a0" },
                { "dsb", "a63714805a0fd502828bcdb6e493e3a3a10b1f638be6f16d867eec85704d7a42e95cd0b08ff6aa6527430870d4e9cbde1166262034c31405d95cbc4ea199ebf7" },
                { "el", "6dc149ae3cc51b52828d3722b1fdcbb0bf16bc50ca87e5ba2b604a1b6b55d4342e9b93d6e625072541cbb91ea8f13cbacd9db879df9627e67b4dc3841c778a16" },
                { "en-CA", "a71e400ec156e9e0a15a1b58cde9b425b42ff047b71d8a9e39c039f1c31b5ba4e93cdaec6e8c9e9593663d83c1776b81d08515fb0308c2d3314e6d6975bf4ddf" },
                { "en-GB", "dc1429dc1d643f0ccec684e1063f61300cc9b388959b833ba0a67ab1c98699cca9da08ce2889c97f6e1c5ca93f58017622a4ec98359a4f1198532f58b4ab0d2a" },
                { "en-US", "d36b92a81fe19f3948df4bde3d2a4fabeae1232d9b0c95ad7b22599c652d0711706c19410a5c96f37386331fcfad62b1a7857014723f53d3fb509c653581e4e7" },
                { "es-AR", "862e49f8ac468a5828866fcc438234cba604fb98456619083cc699d1b01a67e559ab63986f1dfb95667bad4baeef2980051322eb3c6d0f9824470a2284c5d7fe" },
                { "es-ES", "5bb880e6ad8d533bd9dd08e801eb22d129e5fcafa3c4b1374089ec3c2349c2fc14e303151609fda27020d4ed30bc2bee0176f8bc240e82fcefa33bb2a81ce6c5" },
                { "et", "92bfe99badd94eb7996b569ce5c89564bc3ba025fd4feb142ace7ac385e060e7e98ce630c06677f46b436680ccba65088efb7e6ef4ab6131236261bad2a4ed96" },
                { "eu", "5e5b720f26492875f4f907dbb5b92bb7c75730f44c5758145791f7fd677af8d9bf321ba152269ba5b7149c80ec1f415fd05d321af6efa292d12596d4653f5055" },
                { "fi", "7d10e591f0bd8317c0d4404c86a4c02a7c9ead47471c1c1c2dec7db42c943b2c48f9f5efa3d372c2ebd15828c9fd8213ee1045833135ebed3ab48b8669dc0007" },
                { "fr", "529a3995432c210ad749d63658fc69704c136b6c1495fa2a023a4b7656a62d7e8151e54f1db8f7a370c3f3f1e858a9ed7f394092c575d40ff2691aa15c6653d3" },
                { "fy-NL", "c67623a192e334dda2dd0d765033f612175bcd09b9c7d0be5a02fbeb12e0f989942be5a3abfa458a2ea4ec88ed79b80ffeef63b3fcc3bd4b0a47d7179f2f6998" },
                { "ga-IE", "4ed60a6a01a3bbd058fd721a33965148a5e8495df4b955ee0b28cd5815ef84ce0f5996bad74a7455135b34a48eccb9f9083af8ac479d8a4124ea8ba2f52c42e7" },
                { "gd", "cc77a3cdc709f89b256589ed5d95adedcb9b969c9de8f6a5b37337082f7096c43eb8402c34017ebe0f208d7ecbd8dfcc6e78e7886b9372ead392119ef22815b0" },
                { "gl", "9ee159cb6ef5c9aafcb83ff028e996a5de59eda69bb2793ab4a2edad72704db63353e73c77357a9d3a2c16711ef09813ed406b272641b0b97825cc5964939dd3" },
                { "he", "8694eb28b5ae38813071dd342099d891fc0fc541ce0f0fdf109caeb64aac005288b28dd61c76a4a5ff0811c5a733232c08713a4d1cce730ffa2e9860bcf7f263" },
                { "hr", "f80392bdc14ab72c1d466c26165f0dc78976ee9508f263d0d208d3550f5c29b412ef6141a1444b343c3dcbaf69c9949ca8857752345e4c3b941ad2b6da78d890" },
                { "hsb", "f41e8e1e7446fc49085cb05aec4d9995f18e65fe73edc59ae6ecb9bd987ed9326a26f81e43310680df87d71741a4f49a9bd3be8f66894dc7156abc89154d4d91" },
                { "hu", "3d34574c17f7673f5df53ba4c012588341d67cd7a13c88e206ca3217f8b2afa8300bc2bdf3675e175434ae3fd178b90f081398e2170a8427c184c68e210973de" },
                { "hy-AM", "6bec4a013f7eef45cf928c930161cd63ee2a7e63698411f8a5785a637f6962750818efbf4d11011bde2bdc72945cf1f62d4d375743d832e8348640f55e536f9f" },
                { "id", "bffd2819db7af26a8c64c70dfd220147923cb9bd809abba03bc022b7217015601a1f5edfa47e2a11e6aa981f0e74cf97e3116f9af605d7dfef0ee76f4e9cefee" },
                { "is", "a92504938a354ce2544d1b1a782c90bee4175ee02b059bf015b8da0d67d2b893629de9cb8eb2e31e044f6b2906ce5767190e6fc46d26e3a4c1a13ef9121794fe" },
                { "it", "d3cd670ed53cf027462644d66ca50382e37b1d7d8c48fe749c66f2956f19885daf62414f4230ceeff4de03d864f90c1f6a90f8040d3365d133ccffab92daefb3" },
                { "ja", "23aa49955402bedbff38ec666ca05ec68a3416c2675eea25e094873643e04bee869d02d1bb5557303bb76d63f8aeadd5e40ce5a21d901c303506310ad9d0563d" },
                { "ka", "dbf8dccaf44cc7c9767175022c8231106df6d74d5a8fff95d1c5de70b0801775af790d50540208b6046912edd9103390114710ef493ad9bde111d53dd23a4b98" },
                { "kab", "f04b4456350888ba998d91e4d0251831f64deb757c0b05af2a69a69028b377245ee142fa63dfc721176aa2567ee14d386185084a5911e6857c794baf5c39650b" },
                { "kk", "ab7f46a546baf68830aace03d41ed647bf953987a6ba0be80cadaf65a7d7cd9b244dd0fe9acd828e3578eac1bc2bd6844a67572c07ce05aeb916cd60777c5630" },
                { "ko", "bb96493e1efbb77f42d15a897ef54110b3f4229216c7bc474e0720fda853aba9dc06776337deb0c1b57c2656460804924f5f1846ae7b1ab3e80047c74e9e9532" },
                { "lt", "b9f5cab06b06a189a944ad5bb68f15d25d3d42c8a47526993015a7580fb293987109f339f2626e4b5ef42b9383ab44e2fb9d4214be9350d3b6428a427b8cf8ab" },
                { "lv", "2632f705c09e185f016978bee522dc3375c5dff16a78ba2156f235d11bc5e4d62ea294036f0dc65091a769ef7e908d889a03926b38fbf1c594f95419c7f01cb3" },
                { "ms", "cfc2d638a59ecf101ceab41673469668c25c75d7a40f9659206e116324e8b71b96621cfd2461e7b7e00c09f0fd491ed2013b69664daf26aadcbbbd4edb4140ec" },
                { "nb-NO", "645e43c93be81ad1d3c23676ecb6cb842323644e43c9eeb62759f59020a9942f13d7a81600b30b691ae2574f45bc795aa07c1cb26f7e308e3bab4bec6ba13b42" },
                { "nl", "5bd2dd3dff2df72105321ac8ed6515eb62d75772e668cb88579df1c3301a18652e624716a12cb4aba977e98fd5302d4f98caac150004f3879b3382a8edcfac92" },
                { "nn-NO", "935a76ffca4cb3f77577cb3c4f645088aad3b08af6dc598e611906bfd488f3a514af6a8b916fcfc602cddfc83b65d707f764705f967bbe826386610d5095d79a" },
                { "pa-IN", "a0c5803ef81d6452017a578e393c461d0aa9583ea3a79680eb6acceea93267e9069ce5787f807735c7cfdcdca2f4c8e17c8a50db6c506a209b79cc8a37970ca8" },
                { "pl", "a9d2096941b6be4808608825ee84502cffac2fb78d4c615435df7391606960782205bb90fcfafac1b5109fb84fe03f3a8c592c42481b0e4adc5a59aae0fa151c" },
                { "pt-BR", "5c979c7e4fe1efa4248098d2c23d04d9814b3c6c40cce85d1c5390050a57f6c31a2c58c02e4b1bd0d26d3e2cb09be42769590b0e967dab6ad5a219a3b5cdd920" },
                { "pt-PT", "8d4ac9ac41924a97260b0cf185cc22ded76d1e51c7a7209127749632765804efbd37c1ff37a07d20d5b3a6a1f120479fe6e8fcf0acba80457aafbf49bc31304c" },
                { "rm", "476c4eff1691cbfd00506ef1a35f5e0c994a641e2ca235a695fe9cb65b6315f95384c4e9cb23e7ba639f57e16698f9e655914c87b2b33c8b367ff80dd019b43c" },
                { "ro", "9a8e170f89b6257cc8aa1120ea4c36bfd904a31dfcdf3e7fd8173458ae0883f7bec0c403274fc4658668d70137ec008f7d3e6bcd2a8103217508f4dae8d55ed0" },
                { "ru", "e763232a16c9a7796e95faa613182cd6c412272add4d77a90716b385efdb7993bef5b882b580d6015d3fa6ae8f28d987e4e9eb0e23ff785a1767d427934c186f" },
                { "sk", "ed888812445e91e9ae1ed7a95ee214577f6f5315f240f25587c93c09905935e91b21719ff87fb0c3ecf1b7bb9a8918e549fe06beb3af458bc9a80b0b9895bd18" },
                { "sl", "73eb35ba52ed2c870fd9b037d10303d41e3ab003cb68887ae1129946c707a37b4e03dea0b842bd6a328e68ffaba0dea29c97c43098b3f7b1f593cbd02d868f9b" },
                { "sq", "15af57a94f59902c599a820da9458309e4ea7b3ba27480ba6f97845390ecd266d9836675c62478e90eb61c19cd468307f89cfeb4a61fbd530cf5d5bd3011b58f" },
                { "sr", "8da32ec2134c39b94cf5877546282565bf3209a57fe954b1f77cefe117c2501fa4157cb4e98dc9c176374a094d22b6bc0052a6132ffd3917d9e8f5a8ac4f6621" },
                { "sv-SE", "331f6a1c29bb5e8c9d10575b62ee043ed2478b949d0afb9e95e848deca337624d962b2c52a2fd8f00595c506af5c5f0f6c99ff7fd26d435fa29c19f623a6ca92" },
                { "th", "f3c1b2513da79b22ace9d0a1a51106040c452d3a97922814eb7f082f2bcf13fa7778132aadef1f1a853e20ec7226ab3f0305048276f12fb341b59f1c48e2b99b" },
                { "tr", "d7131f9e25d01344d0a22d9d0efd7d23db715a987c18ae8644eaf270cca7ccb5218c8b7e7dcb20ce2acfd8bb2d282dd2760e287c2891a6baa620a201c7e46806" },
                { "uk", "c5c685646a69ede3712dca00f4561e476e87a300ff963c6ae148fb1aee747ff21df9b42d8b8841a991fdc4c8354eebf561304ca7d9f9345b120f9800cd78e723" },
                { "uz", "8de05134c8df787d0fbc615361443b70428e4b31c39f8b155d6c5ca66ce2ab9677935fadea7568cfebc689502075cd3603efb33f164c8b4bf8b3b36ff8d30c0c" },
                { "vi", "5d055364fa4b57e5a0610b981952813ccff0dece28d2cafdc90e1484dfc4ef6841ecc15edd4b3217312b2e03e7b6183fe4e6c9369d6946ad4a37959d63375a41" },
                { "zh-CN", "4db8ac69abb7c69cb58085a3a6186561f3690ccd1d77818ca20897718d53797e35b95ccfea670a9dbcaabfb3b2d880e172635593eb4e76acc037af10079f8330" },
                { "zh-TW", "b5b77bdbe47c71350c6184f91d380218960f1a8456c6ce2d3cc965c3d9b94cc529d0b64615a590a26b2b9ca27fe30e9b2020f4b9e0890d8d8346384c89be4f81" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.10.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "c6521111e03b270112b25312600b1fe51b0be5319fe6b4451ebe87deaf84117451a98b18563f0d58e8a0dcf35b1c569e8ac4d5cded8782351f544182db9e73ee" },
                { "ar", "056f52afedd027ceb53c2db3809b7d4bb33dde6a1d29817cd87e26fe228ac91ccc8c8c65fd1ea27fddd8ff510b4f455cd498391339ac76baac5e0d2b9e77bfb3" },
                { "ast", "0a2b60d5304e160d2359dfcbc8b7dd62337e0f5c940850e46ac7d7fa408d5db4e8ab966210f7c007490b2f874b7d96510d9eb2938a16a39c50b5d5c68686a4d8" },
                { "be", "af01ce7da68814710eb5b72b4d795ce44bc337ff96a14ab5f060ad48c9a963811f0a68135c496a5af2693044d7ef930594a45973f912e38551c108555220cfeb" },
                { "bg", "b362e6329c1c45a8e31f78084be4fcdbb668007cea284c16faec227b9365e5bb29d9273ff02868a81b05c8c9b9126e97342d1798c0917c51bff67603e27c52b3" },
                { "br", "39ad97b322574381d1683362fdf3a8dbd2fc42c5348d9768e1e50ffdcb605d4885eeac22fbe22ca7b5cca9e0cd051c6a18314fc764066e1847d994925a183b07" },
                { "ca", "80c7cb957fc67a415667e6777e830d39083c1045dace9fef9bea942ef6f1c2273f3defc98affebbf9f7ae63e0597c06a28ffe982d25f6268e94e1167b8faf5f7" },
                { "cak", "84e5ccaa67d246dc8f2da38ed856d69fc915bf17d166a2c73694724c4179a55892182a4ed408cdebd87e65843202b77acbb9f1bd757ab8df8ef4af1d6fee7dbc" },
                { "cs", "5b57fdc8a1e05f86027dd59871bcd4ac92e2b4fc43ed201aa7766ebf33535ba4e00e3fefcaccd8ca7d68027ade0ea7d141ff11f0d8c3ded54990c649affc71dd" },
                { "cy", "f97305f59da7f1fa17be8ce9f0c0910d7aaa183c93a7a8eb512a26343a1610fc6f256a9353c50be06a9cb3e9deaad7953b8526ae16027f36dc86991491421422" },
                { "da", "f3b4ed1876a31d643efecaaa005b40c8e8a87e8c5bb9c6d9883283839eb691a87527c2b71f8471af62354691a3ecbcfb9b9fe3796025ffe89ff96e2dcf260e77" },
                { "de", "e7f1f6ce327458fbc79be159d7dc4e2a3e6abb5e57b28c12d2b73f3396abe4aae3cc0c5f82b6e57199a5a8419426bee12dfe80bb3e0096e7cb519ee064d84637" },
                { "dsb", "d2cf9c43ed55d0a434edd40ddb22f034308a072f27a1682d3a86aecbcb76faa2efd932bc26185ecfeadd59c62331b72156d705a9624e16779777a2cc454bcc17" },
                { "el", "ace719426da612b9253ec17fed2ed7594d299c6963638a9f5c15f3d13e9aab8fc4167f8d8b93f8363d07ec2a249d133f3cecd3d2f63d1c91151042ebe6a1d611" },
                { "en-CA", "ff2ec235288c7c3e72650cf4573ebc91f1fe262b8e315aa64b25de0e6cc704004eba5d5dd34ffc375d578ddaa13fd7f4fe581db2ac5871ee9bdc56aceb6c2bb8" },
                { "en-GB", "230eb5c1c20f8c8b18e74089634d696dc6b2b9dd12f1f22517b9ef8ef02221478fdb254ff155e38907fadbaf0bba5ea6bfca9e566b5cf7c646eb284d1bfae9ee" },
                { "en-US", "2ee77bb44ba7c3dc370c7bdeb3819886baa109227d0e5a21b424eb205fd5f597603855f5422fa39f498ab89a203fa663635b305d23b3637313ebdfa606dbbcc1" },
                { "es-AR", "3de15ffdc9d5dd530bb44c13c3e0eb565d249281a33edc4a649a6c971f32f442ac2f6c200851d96dc173d272d7b358965b0c7819c364f7cad6ba928ad33ea8bf" },
                { "es-ES", "b38b16034108261e17ed53c53a3d0c99781574f9d64324e21c5e689bc3bbbd40b6f89ecf1455fce4558cd6df0c009366b9e4a926e535c253ab2092571df022d3" },
                { "et", "28977c39edad85486d72e13b8fc538f73200375d1c544221f498802bb8069ca1eb0856d7c7b1ddb0ecec84bc38a9822537e88af6b407402761523598bc262175" },
                { "eu", "33342895c8a17e6e5af2f485f6fa9ed3ab61480a0534531a6246e5433b8c80c957962bc1286749c211bf69067961e813a4815696ec614d8d12a9cfaabdf8ce05" },
                { "fi", "f244732d3d08f0857c2ef5375341cc882ccdd68a7f621c0753f1ebb06601cbffab479af0bdabbd403ee0c4359ce00161c9b9d1cb26f111edf5eb8e098662998b" },
                { "fr", "3b8303b3f6f5d486f0d143dc4b0dce32c030228d452386028943a35a7a0547c84cf60ccb4fa03d49384e1eddab34f0aa001fd06b5db74b248af5d7d4f72ad04c" },
                { "fy-NL", "930d38194200b96ea643c1576758a9d6f94234e68376efbdd45c72f6a37562465e3172be74135dfa2891fdb3712a7a8c4c7f08cafea2647e739e6722427aef65" },
                { "ga-IE", "797a2ec34f864032401f2bc17bd92e8d41e7100541e5fc09e2d6e5c4e9405d4dded024f4594cfdd992ba3c13b6a31fa7021735b7ecf75f44b15f022230c829c1" },
                { "gd", "8fa3adc58c8b4657f87ecc6ad32ef406d58306e77fdfa5fdca15e96d642ead4050b744ec436e77933b81f578baca674f8056f694941f1c8526ea204206abe279" },
                { "gl", "7e04bcad10642abc0a0b5d518254417daa7fd64ade0210611c38ce4765624cdf6554a82aba08f71ca6a0caa1c6c25a97c57c49e27d2597df8d6b51881c03c09b" },
                { "he", "92090dfed612f6b50710d09f572d369de1b6e48aacb5e4d189d7b2c471539be875ee1d5273527397fc077a9b616b75b8f37667fc47b30ced73f91c5b89efbf92" },
                { "hr", "c8924bbd14cffe99281a7b409c29cd09ce708e79239a189e0d84e4b5d0861a3426f9970f77c6a7f8fdda5778bf592a4f232a8b2e9d9153e998a832c83d62c41f" },
                { "hsb", "76807341d81301b4641abc3ca2733d1e17bcf1a9ad652a394d35ca372cc783ef122be6cf99a76f452f51e7cc454627aacaab92cbfaab779b476c53c3e7291faa" },
                { "hu", "b1ab0681c3e311c60b58b98c05e51bda750f2804f0ac5dac98bd8d37f09003e258979cbadf4631ab8d097b7f8e66978a3e52f75cff001d2c89157541f119e37a" },
                { "hy-AM", "9bb6a4e53d2d264f11b20fc8bd6dff64a2a08ec23849c0c381df9a556eb87078d4ad9f524ab8f8c28b70ac30909389f36944d28d5a7b4bf36a7409479de676b1" },
                { "id", "1beb3c69b8a3f0d6fb228b2fe846d6b84d988de66d7ce054632c98f1786fac8a88b8f18380065bd7b50a3ca4ea72c9e2e0c1da89792a76016628a3c2dad27ad5" },
                { "is", "a6d20f840867202dd2d433ac93dbb0fb1f283b637176b508f6d59827e70d77b6177a829cf10a0b4a5fa38aec0bd2826c3a765e922ef5c00e71af55a0f45c1479" },
                { "it", "381ff43d784f8f4093947591485fda27c0c5ea0a7909093daa6a7890b8a8c5d27b0b425e4177473c68e64f36c1e7165deb9a673d78774e017a796ccc83cce01e" },
                { "ja", "149e19e45021c2510e79f1bb81328e037b246d745e2378b57a83466abbd30c9c45b0f0f84c4d831c086ecb853d1eb2451854a1c0d141524ed615acc05691dc97" },
                { "ka", "a0731bff8098f365bff709e68bb489516719ccf46f96a8501acdf1599bf79dc95748a11d10e70227ea0453e6ba17a4748d5aabec5e0207b345da5d7bf8b0978e" },
                { "kab", "d4948e14242eee2b64d4308edec9f811c81aaf0e6c528d37fe0def7d804cfa9da4e640283c2cac9264669fdcac8eeef0de839649530ccfe0935113bcd20d2cfe" },
                { "kk", "0766c27ca60c456c7d6319373600d17581afd7dfa4bd726d520cddb2d7b25dd1ee9d18b1407d9c29710d805a9473b2f22131ec422b1ecfc9b2d6659db593e355" },
                { "ko", "3ebc032f4dfdbd96563fa8fad77e18f35112bffa1f8a72a12a12ff76b3e431b2681566c0973147e9deba2c5bdd064376bc22a6a198472c3a87402abbc4190ecb" },
                { "lt", "8b8d04a36f3e389bff1348313a41bf06dea2cd36790895e983ccce2b833c96a1f31a48ba41513f0034c4d5770cbf2d611e837edbd3975e5916170fe45ba72e77" },
                { "lv", "31ea70d7488178bfa4ec4b5ab44c6d7b3e5ea71aeb9a924aca5d62965fef3a4d6abcc3b15740c7c8582a706c39c9f6d0fa631a1988e6a631176ef0e00c76df78" },
                { "ms", "f48657bbf6585c046a089d8e0adbb1dff2226838984bbcd5df0f8688a35ec2734f4e5a9899d475223e0d41e3dc21e100a196d89b6a1d64f1e9a81f53dab70039" },
                { "nb-NO", "211868ee38c32887c9efd62cf6ebf4219424cf1b6ec1d7dc1ae70aca89f2944e1622a595cbe3817873dfc4fea905c10c456640a51d832e2f56e21c6c25592350" },
                { "nl", "25d56f6f451e512e588c0d779458c58faf2dc2311a75472c439219fc92dcffb12973b22fed6d635627dac98edd957c96b4dd180672bb53930d73dd01c480d688" },
                { "nn-NO", "c704ceb9b2e666d2a10b1a305eef9108f3b4dcf24d8ab4a575ab3cd0bec35b57e5eb8f6321b2fb55fd105f5d7695ab8a4330a74591980ed5cfc5d30e5192e6af" },
                { "pa-IN", "a130234ca5ca68c947425789b351af5cfc9ed3e8ed1727eea34b2d792ef8d2d03cfb095cc40fd2645ac2c3b29322be76fe588a652a5df80abb4a40f7633a2c1d" },
                { "pl", "43b5b07449d709e64ccc6060b7b2cf1f300897889c1055c67256d97dab30ad7895b2af31241547986df93bb897d2bf9d5d8aa7e8778803dfe10d37a1b612bc29" },
                { "pt-BR", "05f421f38a55e8b40359eed9f5a578b4bcc9da519b7881ad5ffeedceb6a6cd5774103c0a96776ac97d943824bbf365e771037e6025c5dac351d3fafb367c7088" },
                { "pt-PT", "7e3059ce4076b6c384582a633e3fe74f17f0dc4a0fe7602cc32bef11d4783bacb649fda47c9e048b9094707b06843aa13c2dcb16550d5243a160a40109e857e1" },
                { "rm", "a68bae5bc502208ab7e7a5c7e246a788f977958d48561c2c517a4c1749cc5f0e97160c4ad88fcb113d758b86323aed4c174baf07e31b4ceeec571a5748ac1dfe" },
                { "ro", "de0a10a0eb693a7b563e737b9b97b980d98f3a0a4a183cf4290c4ef1f6b9ca6cfed405c5e1b53e3a17284b2fe7d540e01d1bb882b993b96e34e0a20a09bcc4ff" },
                { "ru", "4648f8c0a7e02cb63fbb4a148e4edf5206cab97a55e2617378304c4ac765ebf98a49251a061b6eb16514c4c415fb60d9f1ec268adf9d72490254d24c05bca305" },
                { "sk", "8c6f636ca6caa1b91415944467d10264a088b128a4a3385d47542db3a89f605562045000e319448c425ade278433d4e0506dca39834d43f877f3ee4dff0f8b66" },
                { "sl", "50b0d10dada3f74bbc25bd3fc39e4dd07f15d4da7b6edd1e133acefa01891cf7c066901205d0c5b5bc1730bae11dddd247ca11a933b94c2f786c5870885a5cf2" },
                { "sq", "e0be4b749d7a0c0f4088fb141f3cc0652f57772e5ae334d1e385d7854e2b8681042ac50136c50360392a37307ad40bad837ef21db3d175a24af91f097d09720d" },
                { "sr", "75a3d2c57d07847b96b741290a76cfb4ad75abbb396ecda1edbe94c79bb490a3a87fe9e9e197d363df5334ce5c691b72758c245a648f7e4560fa59551b0f30f5" },
                { "sv-SE", "a7a8ffc765cc18ba910b1a5e58d44b579f01fe03642c57f2419bcb46f1de58b1df36fc08abe45aa3b33c53e9ab19372bc6ff823c8b68fba8f868fc3483974c5d" },
                { "th", "7cdc6133d91a13110052ade9674f164c958f188ee67bd2deb35e974e939e6ebe4116be4b514ecc1aad632f4695ed4426040e81a83b63347bf27452950cb4e6db" },
                { "tr", "dc3574b7562415899bd8cee779a906c490ce112e9dc28f3577741347cdbce4c0da75368d69783881bc9f3e18d1c468183d7a6bddf9c702942a561fcc10c7d600" },
                { "uk", "2625a4656aaf2c343ee5aa071e4957cf5b23da5a1fb5f9a8dc9b9d3ad4603de293f117779b5a91e88f2b5b5c29aa66c8bca5a74ee74de38142f0d2d7252966bd" },
                { "uz", "021312a0a2b5eeaa41ca449a19f88734a9dd2e9a3d57f0bfeb470e29b9daf20e2640d5c0a502ff3d7222e8e3f888b1180a90842d0b14fab30ec5baf735d58eaa" },
                { "vi", "11dc7a97661294b626e0d3ce2398d534bb6a245bed169a41642c9541ec8340efc8ae938b8455f10a5770d6739533012d49257817b6846d8d737db1b0de055455" },
                { "zh-CN", "ebe74340fc7032f55c8b78884c12bb1fac4a3a155ea16bd9c9444bec9acd7c4c6e192468bafb3aa651e68bdfe1b5a7f8f8ca899dc8245ba723ad02deb6ed3f4c" },
                { "zh-TW", "17608c87b216f89b69b57169b339f046ab5b00bbd9ce99bfcddfeffdbd506c989993bfce467bd00f0c81377bcdbc2d3ed4968ce58d29198ddb8b8e5f53bf5e52" }
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
            const string version = "91.10.0";
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
