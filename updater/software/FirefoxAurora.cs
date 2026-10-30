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
        private const string currentVersion = "160.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/160.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5cbe54209e32899e9d391c7cfd216653234d8f6f39e61d2ceb1331eb77a804eefa15a4c7a38aae26bcf2d8c399663cb01cd2afca16211fd13dfafccd3156d136" },
                { "af", "bf6c01130bb8d6b259b84622428e6db40bb5bd24d42ab33897a49955c2b74105e016be5068da54e615a05584560d2f61730e2340871320487dec5ff816cdeaed" },
                { "an", "6220d4157d1ea17761e575683ff2c9a2b01e3332f0e14720f44f9cb310dda0a8d794cbda9d25679ce43ff424de6892a9a867fd3e0a9a6a12188a2554ddcf93d7" },
                { "ar", "bfe3c175a4907f18d7647b150924fbea7a2108aaacf23ebaf9c614dbdf417bb824d7801699b4a0ad22dbe39da81314862874d3f2615f5559fc738ef7726bf044" },
                { "ast", "0a327f3d0d991a1cd731e495062c5a8a4df5257fa8980d73c6d58100bff2ad4fdfa87400012c63a42180cef9c9330ad4418a55be145568de6ecd19770d24d233" },
                { "az", "ba0b24934843f4092806fabf4f4d41d3c1230035f4f2e7c3d98d572f4b26b6b0d92c7b27dbddbbcd8894c34ec97165c56fe55f9d0dd801cf376ada2444a70e13" },
                { "be", "2337ba727dd7e3bd31a7b97e1694b42ed2f2453fe3e555b41e9aaa8b24a072c068bc89622e0d8f022b627ff6c4ecb8e51fed968dbf645db18bbf648f302a8738" },
                { "bg", "016fd7982c1d6668fb987f32036e8c71920345d179876ce7503c6e7c35d7f73ffab31728b3bb614a2679d5455c80e8ffcc711f067451cf0e95c3cc56fb86995b" },
                { "bn", "eadc2545b3de88554895d7fd3af1dbd093d078579557c63866ca56ddcea562a1b001adfcfe29532069fdec238aa639006b5d7b5f24fc7f9d33d503acf8a98b91" },
                { "br", "2d3d2a832361919191f18a70c6ac415ddea9c3a951b8da0a7eaab99ab7f32a8322e6b086ab4adf6a936a2ae495617e509d0f4cb354238047571f23b70ddd1289" },
                { "bs", "88e9a7ed266802163f5b9f1b8222e4f699b872f576c7b4162229be5c18ab3ef4cfc8228aa7a0c8c8fe685e334bd4f433c14f2cebb51a8a5da5042f6be15f781b" },
                { "ca", "fb4d88c8703bddb244edf8135f373e54068bc1c7e07612f99b948f77f86f6c893bf36c4b7298ea85e093045e49a9fcafd22fdee59d074711d5c32d6ecbe6a1d1" },
                { "cak", "72a75ae515d1e388e4fb95c9f035885eeb07d99fa2ac7beb450cb60bfddfa6d5172658573bc89baefe49cd6c94320b9ad5ab97b08c03810bfada278c122a678a" },
                { "cs", "f9d4e08a45123661adf7c385a08c4eeda86f75868251fa6363bae5c2ad4f2dc2d8d9e167ef4a308d872518f62d856fe020796c813d6681208cae1c25ed6f44db" },
                { "cy", "af611ab6ecdf22a8705ba53d9370514c201c9b0b8aa636f9bda1bf1e4bca7ae2f814d65b5517d0d7e367abc72a2a507acbcd9337e405b4be3dfdc514e184356a" },
                { "da", "96a0c5a33e2c2c5f4a7b8b81ad5f345b304848dc57ef7cc299e3e12fc473fb2e3a8faef88814c5bdc82b32706ec492976860d8669201f08cbfcd6d023601e2c4" },
                { "de", "2cb006c646a9ca5c6262797fd01bdcc40f4a15ab0f3f80d232cdddbb63708ad04bdc4b4850318ef499ef9c2df8bdbdd6ac0ee7aa05b3648745259cc77ebd998f" },
                { "dsb", "e86ce0fee860453ea632c60332c59d6be4f4f351aaa97cb622556239a95032e92aa815f0472187d05a3f73ce8246cafe369129096f5c2d5dee3ac4c5ef876408" },
                { "el", "daf992830206caf3cbfb965bbf0624211b304ba45c2e3e1ec7a4f655179ceafd1aad9d762097828bc601addb44a0309ea492c8d9d5ab778d89888ee1d81b5c44" },
                { "en-CA", "d42408bc7ee960decc26b49edec44e779cd1b2805d4b1ed225d02165bf06f137b5d8777f2d6b53d520fffe6adc59d5abbc4a229a20c3551dd4ebfc8e48ab7fe0" },
                { "en-GB", "04318374f0d7b3d65e705ffda7b6cb8825bd661a8f77c920ac7d92afc4e399fa53937fec0793d43af0a8e283a79c05bad81976cece6fed81a91e85a1bbddf75f" },
                { "en-US", "5b01df9916d48653763dd82df5037a5fa1ebff18f741c651dc61b61c734e5bab14daca468385e0baba0c899ac576040dee43f0d7acd7518bff4de6744a9261f0" },
                { "eo", "64844656fdef8cc4134c01473ed8f9e8414595cba484168a40ee0487cb27be76a8c7d1f00267661b0bc5398b52642a476192089fb31ec528e372857062eac325" },
                { "es-AR", "4b05db2f751df3b4473061567eed3b8f3dcbb2ec233b75031a4d577b8db559ef1829eb50dfb1cce39c8bf60fd629d2308a2110e540bee1a800da112990902564" },
                { "es-CL", "6842aad6dcea123c66367da4c73d012e8de3e221c2fcb7e3ff9e2d79255e7bee8043f05c5a00d75cd97bf9d211e46c888920254d7fa7e0f8c9cc22a45b876959" },
                { "es-ES", "5f783b467015a887955e2a5ace0862c55c54f6389110eb7770481dd22b0d2858fe3a3d4ddd8a0c3ad7a95125d2c5bb9b8e1f1b0979cf3acf0ef63f892cb20747" },
                { "es-MX", "6a8bc5915bca3172b2c76e02eb110f6661ae5cd767928680de1b61f47ebd514b20b8a4066e5ed8bc56408537e035bad7086550c75d0aede7950e87cda634f64e" },
                { "et", "3a1dad940674a25732a62594ded99dbd816038532577c29f973d3473ee2b1d9915a34e38515c54fcd2fd173fe508087b78b37a2e76de627b94ac9eaf41774a4e" },
                { "eu", "9638223850f5dd6efc0d06fdac680bbd922b451d41a31ffdd59bd6b3515fb7f6ea1d80939556e76416fefdf812489c162e07996fe92211532fbd4ff638d23222" },
                { "fa", "4b4e1f7a9164efafc6ffcd41c56065441957c912890fbaf8dc8f3b6a8377c7219f1ca80998a746f11af5222670a04d737f0ab59b4596f95b868aa143f4a25a6f" },
                { "ff", "792fca0ba27e7355020e37d933ff795db6d771a9e4a19a102e51ad9475d8d96b1b3ce233e667575f6b9e6e45cc7add8c2fc949840d93a898d5d55599bd58a5b4" },
                { "fi", "3e15b670c4a9055ba971f130cb08672790fc77856cf060561ffcd986ac1f78a159d049501db485cb4f50b078a1d645a8962ab4db3f55f77b2c539cb06613becc" },
                { "fr", "b25c714d18dade3ee0593469e2625d1e7850e841d4c058b3bc83070a7982914f0bc3700446d9111400e3c2b39308b7f858df44a5902b03319475601f6d66a642" },
                { "fur", "ae8cbc735e5f0a20ba45fadecc312b74357a621c23fa84c07b9f6762b86786433d33dbbe2234c90ccb43648705adf05c4081b81b0d00964857ec482902e2a968" },
                { "fy-NL", "56d9bd7c55b24f28682a13514091ccd540024857c185a44095b6beffc655622128e13680a3525deaf3805bc77fd711a66d6276275a67877d9c9c0776ac4b02e0" },
                { "ga-IE", "aa580c0d0e6b5826ec5520b02fd382159eb3c9f049d94c70fc320b490b1f77d3a2ef6c03578b6a12179fc6205822da9917d91ff02dcf924f55d8945d9708eef8" },
                { "gd", "2089f9a3fa06edc2c735719d22e97477d93326dba90797bb7c78adaa3940799656896f105ddfb46fc05db78863a3942ab372e2ed7c66e1bdafd5a5ed70d5de1b" },
                { "gl", "87ea2ea69d9372b2cb2e34621259f62508c76106d004d27668f4880e34ce3f0a07d85ea4898d68ab9fcc3d37c364dbbe982a38fbbfe8820c05e8faa0601aedf8" },
                { "gn", "6861c7a08041845f068298c0178b9ca82864aa6ed081cba281b99824ba2036ceed5f78429d7a76c838c6b134e54d75bf6875fbda0fdb87378bdf9aa1e486df94" },
                { "gu-IN", "66bbf2ce0a398d719e1dae348ab72dd85237ba4a77138bf4164f0fcdb3732a933b178c5955e92dbaa35334dc8c2191308fe565003017d66a6c569a7a9d595264" },
                { "he", "5e3bb0e63cd4ce0be74385265bd32a9d3def6ab5e57c262b85ec7fafa39067fb71456acfd165bf81b5e67fcaf7002d9c7f6b6d30d66c96dcd8384988fcb13374" },
                { "hi-IN", "c18d4914adf2de14deb66f2ec904e00c72831cc57e2bc8cbd431434f114b19c88b15329ddd0dedf0ed053b7283696f136783bdd56667a1722a16c8f17a54dd81" },
                { "hr", "de416a8461bceee205e3ec6284566fbbbd82ab1e3ae4260be4d0f2207e4df7dbc4ed5b7c7db7cf3064ca86a91e3c5c728f98c1735338e6bff98dd30cca256b6c" },
                { "hsb", "25897e4e5d8f665c54d4032092967c7a2efd5fef41c932ca1d123b2e948c37207ab8e426644855ce2a0b55a267adb51ca297011ac6ad028ae480a2f414142c85" },
                { "hu", "6dd3a309828503745f65c34d520c3d44fb824b7ad71b7987470b26240ddce8f4ed8e21bb5dce5b73b245a26eec9e57280aa1c9c80bbf4a67ca44d6f60700342a" },
                { "hy-AM", "c303fa81c4b93fc7e1fdc1b0e7f032afa4c35f5882b8766267e6db6dde98873f4a370f5aae65713d25946f2fc19b8e3a268d04de77c0f0bf09efa1637ab8316a" },
                { "ia", "9da80120b360a0cc5ad84d05a9341968613cc126eb79d7f5b53b46ca9a435237f566093ce931d662f68a8c5c134d834c943853d5824d33bcd906a334f1424028" },
                { "id", "e584fa8cf03c2a5722fa3c305ff7aef429eff14832280cd7dd6d374bd782fe43c056650ed5dc4696f1c5b1900ed44aeff1fd5cbc0b721f20106594c52a69d2d7" },
                { "is", "95ddd61188dd5740a81ea318686adbbba2830348f149ef7cea6f35e332b896ade121c6143031dfbd40ff9541f25962c54e576f68887c52aaf1dcbe9836b77583" },
                { "it", "f13dcbf8f409838c130d89cff8405dfbcd3eaff8c9e83581062eca11ca30b5b08bf9890157a6074ffd7caffcabf6f8d8519d18cd5ffcbcc55a105768e9f31c17" },
                { "ja", "6ea189cbe31bbedfebfee91ebc65f36c7dacbf98a96e10604331ad648575832dd55fe2422a31353a836a75ffe689d901772f649671c6c69ed40741b83693bcbd" },
                { "ka", "df76d59f15223d1b10d5998f055cf6e0053a457df06c6cb5450fa499a9a9cd057f166431c67e5649ed2e22e6b5337a92785d56c3b320e85f4f7771d83f60a905" },
                { "kab", "afcd691fe640def4ee2f818ba80cd2eb68616bf7e2dc29262695f42d99aa01221dbfdf35c8d2d670b2d00c9ce985b68eae274925af448c1ca9864acf74574b25" },
                { "kk", "03f32f91f6e9139ba23055ce6428470d52ca9b1050441d06961f52de738d22e75ebff44cdbc856a06d3cb09fc85cb9cc8baf52e720f34563d34131b4c0f2061c" },
                { "km", "72ac4194e810a391c7a0f8b2a00ef4d89ff45ecb132c80302f39b7e1d249e7afe7ca3d07241c13611e89c71fded68924e8a5841c0dce12debf466a825bb672d4" },
                { "kn", "59182978c7cbabe11f0735bd8cb7b3f89f12574f18032292c299570afaf8a25030275889600842f60c093a393fea9faa92aeb4b5a493018c1c4377fb0a961765" },
                { "ko", "ed3130020be85b256c06a893e6a1057398cafe99bf7229b341b642f7fae8506d21fe4e273084316507518bf751610156d265f656399a80733ef23e5077981d09" },
                { "lij", "a065c92fa96dbb4d121427c3c7c9f9aa778a064f5cb0db1d0632b5caa23dd3c39402b7f7b4ef022cd56dec5c2cc7aa1d62451dc40a5bcbad571ad99eccbb8a65" },
                { "lt", "ab1bb94db09cd2ee2b46db5128e58fd0fe0c12b792605a74ad0ab3a3d43626c3d735d7ba978e9af9bba4d787a8b850a0ddc8c485a8fa9eac5a6de18809f76538" },
                { "lv", "14b2b32f5b015de666db3b6b24d76aae37850a1aa28af40fb87a99f850f44ea5c60fa78654234a806c90b15da4325174c3c0e060da168e5cc022edc623c2cf2c" },
                { "mk", "2d9373e922f2c28b00b2041b21837b902a82b39080cce0fce68c6844b708bf2220399cb6e471d154f82417803c601fbfc530da27bdef5521e286435b979cc19f" },
                { "mr", "01d4e7c16317761c59b8d1630024995dc17eaf7502469f556cb60b7b8ce93f0d1af63f291d50031f9f0dfa6684a1a18769215607ad2f28592bbffaab81937259" },
                { "ms", "a90756126c79375af6a5d4c65c1157783fcf98b4ebb0d5783ed351f8ea6e7f9b06837eb41607a06d1e5543cfc9cda2014151881f715f747e57293f970bc95345" },
                { "my", "652d3d25aeea2ad30927d2bb76f78990d06ab351f05c05ad73218853dfe5dde5fc489809291424494733b6b7273a6fdcaae7300c404e3ab4010ff9118ebe20d0" },
                { "nb-NO", "bcb515358c302c0476bc302f5372c8cf03878b9f999d15f0836183fe07429726faa881acb52f8e9eab08f26ac36c8f52a59386519c7ebb047fc634b4b40a9907" },
                { "ne-NP", "47bbc6495fbe3d45865a618cc4a8db54906245f7cf11c159157e65fd1b0cdf0ce2dfa910c6450d60aba03897acb6f97407d0a1b4f3101d18a4d3d6707a1da2e3" },
                { "nl", "f953d6663d7f5eb8c736c21b4457bf633a189cddcdf7581269a58c9e05320976c5046f7ded133cf1b9e016cc9d70d698c75f9d4a8cee37cf32ad517bc62162f3" },
                { "nn-NO", "b4d7f4d81031ed2d1ea6b2f96c166083891a341fa97715a8f7b39af88af11fa01a067ba2d67ebe1295b04f006b6bd4d9e169ecc5834f3a80a603693455a7caec" },
                { "oc", "901190ebe2ea997f816b34329da3440215b64e73d6556519bc7907d7cb68678734e81c0ff8b1f268283591a61606290557c53b3894cc7498816e7c64f66ccb19" },
                { "pa-IN", "be57cb1c8dda382ea0588511d977a22d96ad27f35f88b43e84802cdba4e5472a34a8d8804169ac29f14576eb65bf2dedf962cbb5e023ddf1c7faf06981fcbe01" },
                { "pl", "4edd4e2247dab89a6844003b662c6cb794b7e4dd79adc19968d061456f62ff6b4e0190fd8353afa82059e0f0ae52f8c7790dbd22bb28f716b78b32e82ca6e596" },
                { "pt-BR", "2f80f09533f8a1c6256745b07617ec9c4ee65a2a966a0096deb149d809598fc35c785a9b9358c14e1d32461b2d5941d88c361a6ac343fa81595523d9aff0d1c5" },
                { "pt-PT", "a855cc037e95348033d4edf7f89d3dda4a81e17313804c2d587ddeb5658eb9c9ec10639817f56cccb37714851fd7930b3bec55f78e9c37069e96b6063b0f3b44" },
                { "rm", "b4c2c9de5d55707671226476a684de89e1aa871ed5c3737979758633390116b41aeea3ea9e0cf2256e665b0ed68c0ae92714019e54410f3cd0aeab10fc48fc5c" },
                { "ro", "d80224218280586d4ef53a8f1aca2de09922a43f961d9529863455a95031f5aa51c87e79669f3a555a62d39d1f12b178282eddc4739ab0b1ffc1d30bb2c5d20b" },
                { "ru", "80d6081a12eabcaa691eea7cac0d16264b69b8885df0b9de875645c98fcc00f3312d1dd5f2e0463e816f33d56dda850df57ab6e9bc2aceea3d22a1d3405bafab" },
                { "sat", "0b6d38e94abe455af7967c29fb2d4b3c029e29041d9a88022c254cc0bc4474647775c317db663dee1f764b0bf70036de5437240f6bf72124dd454f3afeae0ab9" },
                { "sc", "36b5abafe7aa6b9fb7e2a7ae4603983ba61bb514c2e930fbb7f102a3652178b6e7f96a0eb468e73311b6a30811efc76741f2ba24add9bb14236287959c275bae" },
                { "sco", "2cc7f22d9bdb2d62cbb2e02ab336427c6d0e61f900da063853fe5d3d8708a97ff7d767fb1c878ce6afaaa7e4be449279b2b9f215288741fec10d6f566a349742" },
                { "si", "784faf67a31792b7597b4331eb0f2dd0c213a3175021f1bf472cc1f7cceb5ee3c30f45682c08d28c8c773454c468c7351343d45231472a3aa6a9d75843cac1ce" },
                { "sk", "ac8f49acececae056ed174dcf7d4c719132b11a9742fa5376d88770ec31259527a65cb5180da81c285752083b81963a4ec3cfb510bbc9854b9e75fb785b82ba8" },
                { "skr", "53d7bd58f71f298ff9ce72fc15a5a7fcf63408f2316e49b7a3371f6095232d9956fcffbea032a905718d8a09a83f29526f267925ea15a38e20b06b40caa8c740" },
                { "sl", "449f994af68fc7f3b121fe13061a2f1d9a08e955bca83495903b059c78f30fdc5fdc564f82b0025572fa83e6ecfe55e6b37c3eeb30006a308df3e96d305dfef5" },
                { "son", "902fe9632e067304b199785dbf692cc86c92597ac1fb541983faa71944b324d4dd7914e49e010205e105f69dcf51734bf0b206d224da09be2ab216cfb193e10f" },
                { "sq", "8d0e86bfd7d34e3992b2fe18938bdbbd758c8e8ab10fe10b049b0cdd377bd811ffb71a5ccda65a039e8edffa9c418eca019d6ea3e353c1ae2afd3d9aad72966a" },
                { "sr", "db773a5f06b853661e50a3871fef486bbef2bbad4fe52bdad90ae8a24145dbb183cdf556541d064900e8a3cd111ed09fa3e636bc458201c50426f29381bbae88" },
                { "sv-SE", "44e12307ef6b1b7a2dbac175bbe1fb7bfdfea1b377649c5c7edb24feeff2299c2d078988d7e063bca2c0869da4fcf1c2ce27a508d520413762ec87dff5b966f5" },
                { "szl", "1082bbf015ed2dda702fa255551f4043daf80472b64bb919f8b666a55770c9b094126f3341a6cf26bb8681245e47e16f84675c5f37baa7a4fc7763100780b0f3" },
                { "ta", "4a4e2f484b6e0944f286bb0e13bd135c0392995b5156098c9b2e0dc4fbabb428eb394d365dbfa96ecd5bc964e00dcd7d95d9ebf8d103afb05c336ccd7b705a0c" },
                { "te", "67ddf1c82155800da973fea3a62441175c34e5509309b593f4104a755fb1395b7b71276b99221b03c0622a974edf5e67a462c64677b815a023fa376adbfa0553" },
                { "tg", "be961eeaf18535e0f93a57908bff334f36e5411d70f97841c8dda0be8e3272dc5cae13f23336c216831067401a4e8eff607135e02cfb180adc9652d5fdbf17d4" },
                { "th", "45f2b32408e45de1aa9f8a4ecbb7a618f7e60182c18923bf83a93084031887f774eb6225d9388f4122aa17e7f8c43d6e379a57cb4cd57dab705d218e755e7ca1" },
                { "tl", "db13c016b99c41dea61fcaa95fec9f8ae6b8174be0c95c72fe47938cff0a8705d22db25804526cc3b04712b26b63ae6ed97374accaf914a8ce9406a25ed38898" },
                { "tr", "0b5c386a4641990713c935798ba062aab90df79abcca15ae841b62ba6dc46ee85e39a060203316c5a9ea3c4ab428f8b56f99ce95de69b6c7ddd3c4de99fd9f6e" },
                { "trs", "e0c2decf8b5ebb149b988227f8fcf7425bf237de2048eec60a28be33efce65de65886140fe66ba216167f625c3a70231ba60aecbf379c9f64e6069021caeee7c" },
                { "uk", "7c1d41ae97ef5ea3f5a1c963e4e85d7fa94d39c49fd8f491db9ab599da3b3a530c82ba23c317efa3c2c9b579022dcbe39861bf49f18a4ca167cb163838fbd904" },
                { "ur", "2c58ee6a2f3d6ba8e2d3b4447641e0ab98eca1b20efbf46ec092c07f163de1f90f0ebf6e7591cd601541817d96cd1a8cbe414fa6a37cf49a867276985dd670b9" },
                { "uz", "3041c7a6d4b875ef74bdfb6fe95b4e7d9463f0939c4d7b57f87d3201e9b6548c908be5dc71e94fa3581228a29285e34b9a6b1eb7af41508eec912d80678e6653" },
                { "vi", "ab71b91621635e86259db4f117dc7fff0606f2cb2271462abba2c60da8af12c9e10d9632d4f12cdec5d791080d9149ae4d8561007539cfa76c09c696f35625ad" },
                { "xh", "085a7aa6ca6a7818331b0d1e057b099c5b5a4e6ab7f9a50d5e779305a65efe3370bb5ecf09194c720d3e923e23f7ceb91a70b9109eb5d6ff182d50aca91a7e38" },
                { "zh-CN", "d91088d2a71533f1e62914b600cd36e1a70352342ec7d88c0d8f67498b7653411ed207185a6c9043a4d08a17b25821be07c3e9cba8b6d03fcff6c65a83a13663" },
                { "zh-TW", "03b62351ab0c9b3a8cb38117b9c06849740ad916b1dbcfd8e333f1e823974bf01501ea5de06709185dc21e389d54ef3429f9c8122a587f843478ffad7d8f5761" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/160.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "28fe7df7ed4c206c6defa57025e901788d0a794acf1db83a92b52284147c713840427b35c4252e63a44bc6d9cb9369381334165a2a3e9cc1a57f20098e58fe25" },
                { "af", "92bcce8a2d82ac2222247e46f71582947a169775d7b2111b48b7ff5e50f889fb0b765352eb4a891dceca573edc850372c97abe1118a0d0b9a72b648701018514" },
                { "an", "73b49399d3264dd729f31dd4b545671c717a7c4d25910bfbb289391a256cc6847f7ad1700a78d038922e785289042662f4274072795b927173a981fa1c3dcf0a" },
                { "ar", "0e59b16fd4ba0b800eabf6578eb847b2180658c8e5b592ea92d4679ea5d8ad9d8e9d399a1f078e9df6e8b86a5fc743b2e6c69890f18a915d3b6c437e1973f825" },
                { "ast", "b5372f1dbec8e6953e97a00f74ea8fff735ecd531580245420e8c35456a3e15bd0a98aae4adee0dad272d5981660231d226a1c3337fb9218024650da69fdba65" },
                { "az", "fe886f563cc2a0475c4024119cb0b39a3c74701b5c0e5681c2edeee226ccbc25556455e888f1f9ef85b54e36038491d0232043d7870d7920f0ddd0bd7dd539a1" },
                { "be", "66e628ad7d21f8a0676fe2dc3b3510df2d7707ba7f18d22b5afc3885b423c34814dc3f24503652ae5ad23769add7f0ac3a0d5c8b73f6233e490b450e2e136cdc" },
                { "bg", "0d1cca6529d1d2daadeff1ae000a106f4e11561d5bfed5104bf4c49cb6beea8f0175c0061b1d6f8027d79eda81ff34b331403ef9ac592a4e1b8ec2a1bb52edb6" },
                { "bn", "0308d3b60f784e4b133d31cacd84f85e118fb4b6a93b9d0645e1a30cac0dfc339a2f353b7d0c1a2122d5ae5e2457cc3a38eb0a65c277e3a3ce526b9be912ad8f" },
                { "br", "ecac74062753467f92ead644c38d1db893d67d52cdf9d6bcdf348cf9783c0cd141c4740e6135559c29151691b29d8abb4a7e1cb55dae90184d008ff2d25e5081" },
                { "bs", "ed988425aa3ab2f31baa7ef1d4759b2447758ac0254339f499e2af48b357f977cef1ffb2725474f8678848d112efa1220b9329a2dd4a1dec0a40aa6c824292a2" },
                { "ca", "f45b2e5e533c0d79d8cd4dfd7fb031eed2cba15141005b0bfe4b2d5c68ce2e51240938a9c7c102e4c0d0f9d644a11d2218e883a4699d200f4b2b89205b780845" },
                { "cak", "131dc7ca3449ce0be1d1dc01d5492a99cb1990a22f3d07d87f1a0eb57c4e08357bb8fd9ce738e133cd7c979c765f27ac596500766d6f636c1e04d925fd21da1a" },
                { "cs", "927ef841ee113f0a82a157b2fbe437a53503b4b69e8bed48ba418b258d03502bf15dd89c3562b767ebdfa0f442300d13f9b12904e3f2f5d977b7a48666b62ea9" },
                { "cy", "51ff2e2d442a869546ee8df2012b52ede9470da49af11611529c560dec9936c92a8a66e37fbb32a740f8accbbeffc907dd9f46047e60c2666c3ab265c85ca54f" },
                { "da", "dd0ed13d2fa6ddc7d35ba45c98eafaf037e7ee3cdd095fe7e8cfab62f432271fc4f913813af100e83f599df7d6e9292996d35d3fcfe6a5f2880ee6ae7fd90d0a" },
                { "de", "5ee87a9637b66697dd8455ffb38fc7268b2484f37349f6c85b6449aa215a9649c8c16ab4801cd2859abe016d71ed1d4bed704027e5bbf842a15686c90391d0c2" },
                { "dsb", "aefeab97ab720ba493c53701db10fd94aceae282d47ee9711980f8c26d5829ca62dbd2835808b689b14bd4b009e18fa937dad23f36e2a01557f8ad21c9eaa6f0" },
                { "el", "7602a126393ec691d3fc9c4df8afc8036fec54ca95d579e890cd248c9bb7f243fa3115485f18e093b43549d5bbdacea4ec9aae242b19ef2923b3fd982c178fa4" },
                { "en-CA", "c7f1e8f433f02f95c17e84e389f191e4ad9e83959baa7d9188d21c705782242f18a2193909f0e5816739c9dcf52221ea841c3cf2b4dc05ebfcb3e2f174a86899" },
                { "en-GB", "b1511de6fe5d0a01393d6b7f859b4318b1124598ad45046817aee44bc2050d2af64d858e01e81f08fc58806dd16982d66c519338cdc2ac266c9ec2382a758d65" },
                { "en-US", "64f06777c62bfae6b475f30007bb0d552f218450b741f11e0b20802061b2656c3d9adca724512da2f4ff48a418b3f916db5547327fa83ab4bd021bd36f748282" },
                { "eo", "31d500f23410723c30fa78996b33ed0c4d833bb67deeb05cc85020eabd9d39c58487dd26da42eae0febb689f36602b371d34b063f78700bc07617ddb9e58ddf9" },
                { "es-AR", "f1c0d367fe9e8fe9d608d537fa1484ac51015d058bbf808ff3141f79a8ab5652b72597be4b3bf516463b048a8b0bfaedf6212e9edc466590c65b0520aaade74c" },
                { "es-CL", "a236ba024a8e56a89de282748f8a1a4972abd7c2784fd972a463bab76a9a7a1acbaf81fdc95c34f1c40844a07e36adf4219ced34e8da05bd3d7449a14c8761f9" },
                { "es-ES", "f88a6fadeb7bc0f99f6f8bea5f22e721345b0ea7201048d1243dd2db45b9b0f5aea8ae58252d3b2403aa72f97ce16f3d3633f8381511b17819f74fb5eced7071" },
                { "es-MX", "afa53dceebcb9ece1a9d2ccad394649e677d112315d5b21b2c9d18f05a6018b354863e3f9135cc5a12b02400cab7111627c187ce42521d7bd25a11377727237a" },
                { "et", "d94a9fad3fc6671914c72e76d3134466987b4d8056279237ab7f859c0dd89bdb5423170a9b8790e77ae781a5cc8f34c7b409a31aef96e0ff5fe9b73c23bf4e0a" },
                { "eu", "045605be0db05e25bbcd510e1aaa803e96f0bf515ff44fc6aecd9ef96c72641e8e6a21c0643f18d3bce52a12316695d305e9926e19e0f4793a291e523a04e0bf" },
                { "fa", "96fc090736483c06c832d5f2748f8614600137e1c4530082ebd9766a8bfed57ba4c59011fea75baaabe0922e30c33e4f8d99914e6677193976602edd505bf089" },
                { "ff", "d8d3f43040ef477560464aa09c14321acc98ffab93e1e923dafd774fae3c7b7f537ce00016d27442543d355fd736d0bde066d37ef6051d891a0e822eec7637b3" },
                { "fi", "fc3de5e241037ecc91e8e53a3fac651ac36b7c8a7d925738bfd9f7b8d4f4a0924fd0e3fbe37a75928ca980475efcc03619a2534cc7e9090586016618bfd1c15f" },
                { "fr", "6cc117f54ed01954d417319389d128994b252f8c73743f9dbc8a22ec16b417f1e7ed0410ce62cd907ea6044aab1835317f67123a4a84c1045e3ddfcc0770b3df" },
                { "fur", "b5cc362ede82640b2e940838aa546be17729220bf854f2328192700b721180636510eb021c683724198ac743a8540cb8e2136378cd9baf7918b4a07f37627fba" },
                { "fy-NL", "a3a8161911f6c616d92a09ce7d66cd867c57c734a98a5cce1ee3c118881e6f64bfbf35a71d94ba401816051572ab33d0cab9b44f8b163ff900aace592c1ed8c6" },
                { "ga-IE", "ca41aafcba541c5ba38ab69624fb4186d98d6550cf0fc926fab21ae046fa7dbd116ae340e7f74bb244732953ac236fac6cdea7336804167d7072ab4227242f42" },
                { "gd", "793e066f3dd4acbec037a2b3c6ea75847e7248759b21c8431af570c03f04c8e665c060f169236d1bea58ac9888383798f641ceecfd20dbc300469fa6ec5a4a1c" },
                { "gl", "75577920a50b75eec29b8ceb9ca5669e94e8c562e96028f74a9642bfa791063b3119669d4d028f6fe45825ddb1918cb96f0b48ae999e298a6f7749ae9b281c8d" },
                { "gn", "54f8e4fb86ed589dce841430908b12854c6bb49c46243017a7246a9a57015e8dccd0b64ae1e0f3b46407af1ca64a233125cadc23dcd3e0062e695e41162db61b" },
                { "gu-IN", "896fceced71bf4f281ad13d840b1fe350cc9cd6f6c55ff02eaa088ccf188eb6f567714058b8f75db4a472ccc07acb4ca8f3be14a53e69c95e99f78acd1d5dfc6" },
                { "he", "49a02c600101d6634c2595a029c4fba1679f77721e4f9fc6a0f7ce872e445cdf6ff600ba568afaafe6c127e8144055e3ea80d969556b2536a21711eca3130863" },
                { "hi-IN", "40bb92c16bdad0bd8cf03945c7addfb53ccaefce0193d4965b78a9876d2399e20b318111e2e8b520b32cf19623e4d186ea08b13c75fad94b3fc988fc3d2e166c" },
                { "hr", "703c3b8b1f71fac692dd1f321be11baefdca10bb53c8c481869f9b53833c53460de3241d9fb542063c151c6e63afb8534b69b5858a857175f3eca3b5f82e9af9" },
                { "hsb", "020df1da86223be90ecc69f08be0e6649371869d99a53ea3a67a75475439d5e455fdd2ff384c1d676f2c896cc8293e715db96e7bc87a97aba30c822f59b5094a" },
                { "hu", "36eb5873ce9f740ff89c438710def2d02828c8c2b0ba7a18eca482569797b685584b959fb4d0c42e32463f9053b26afd58b2b2e299069aa76f55554e2c7bc28b" },
                { "hy-AM", "d5cb67ea2c9d7d26f74fc14e63fb302abf0e616206b83a1236603aa37dd3acf421fbd4b7196f8d2cf83b4011f362fbca48af99e1fc04d5159966f3d67e7cda03" },
                { "ia", "2ca59c8f3090bcfa09eb2e0bc5be49e6e0a829f2a520259f8349e2169851d5ff87c29c51373becc5bec29b5f770d9828830bbc7807f01468567ac30a7b35b224" },
                { "id", "c7c4919f380aceb86969a714c11beb5a4c2323384d7aa648af51ae16dacf0308a2b1b8fd71884c165a3a1f621c6043ae1f19cd7e0bae5bd8b97001202a0532d9" },
                { "is", "781ebf288ce37784883ceeeb89498e251334bdbf347f4af927c97dc47555dd5a70f9cb834eca43f8f9c5f7d68d5dd4c80a5b57962c9444df9f1cf4be5f25749c" },
                { "it", "e59b612183b74bf0795087e19a1fdfbb63981bc5e6e66d0ae11fb4455bd19ad8f74f41aae04f9b529e128ebecaafc7ac3917463ac9747bc99c16c330d5dea7c7" },
                { "ja", "810a86134b8d394e5b08151253d3b066811ca92ad00cae77520fda0942a1a442d6dd1e961654a7bf650d01f0cce882b01e21f73ecef65fd6117a922142bc3439" },
                { "ka", "877ab58901f5edc31910227594e7065a85426af0a56ab5dc9382acd7e229341ed207da9d8ea6aaa294a2e3a37e870d94363e891acdf8b6cc0d415f696335ace8" },
                { "kab", "c2dbdb2a8b95a416b2271a1eb1d2235fc25739f19cf4aa5d4cd3c354a94e80478b258836c988e19f037fc42265f65ea2cbd3fb172abdd3f98f818e63bbf04458" },
                { "kk", "434c7b7bf6d085cdf768be79a02d450f1457f809a531833fee63021a41910210104bea1bd9507ccbeea4c0df9a65a5807c9e8d02feadf9d1787017555304fcb8" },
                { "km", "80f536c1fca9ab7fbb7ab0fbef98571cd211c10e2737ba4f12b47eeb37ce53aab32b7d35c16259efc3fef879128bf703725531f5774db0f29cd76101c8912280" },
                { "kn", "f1b2c50e7af7efd3b993d48e3ed6e9af98204e5bf6c1e0e8de5cc6d54c3e0766ef697307729c865f1b2010fa5b149514dc928e19dae5d79be01f5b00ec6bd8ae" },
                { "ko", "a419b64d96566e5eebec89de7585579babf71cdfd969e1705eca5f75930959853b4f9cfd33dc43bc4744073dc17c217c94d1ac1d0e9e36b48967779f40ae8da0" },
                { "lij", "e111f0d9471381ec03c99041cbb8d7251446c0992914ac026cca367f74464f2687f073f0442619fdd3fa0d01870f2d8aa1da3a0add39e5c621492aa4145b3485" },
                { "lt", "682da97789e0379bfc435595183d2db9f6e0ebd227992185228bad5fce889e0396cd77fbf5d295fa95771dc84a6b9f9b5c7ea5f23a403f13a69802b38ee189b3" },
                { "lv", "5112009cf8113968bd0311d1282cac260367a26453eaa3adb9b40ea7ca72681f74ce573b1bd02866ddecfebb6a4452d678506fc8445c472030762d69d6258375" },
                { "mk", "8363b941197b3a141a897025cbd5df54463bea2141250c453dcf1cbae31884b123f73e5a198266675b60d43b6269a9af3f006ee6e2932ca477e1d508a9f06bb2" },
                { "mr", "6b59d87152adeb4c44c6f85b1cc42ad61776d1ba6a3d9d604bf8e493e90a2438c6b6cb4096a2626c9e92edcf0a4fe3436a7a7d21d526a90199684cfd6c6ac13d" },
                { "ms", "72de756465e4e59326da797b42d66e99d366c5fe9d438f2277ab8ee9485583018591dc712d165ba9859c7b0bb8984b54c5e515778b7c45eee3b810b564140198" },
                { "my", "9c3110b0b59a6ac840bec6b754e4d871def4d9a9bef5b4e27f5d8ac3b2fed419643dedb28494e072749daab39716f7c77077679174a4a972e1688519e3b5f41a" },
                { "nb-NO", "a547737e8c37f8b73ca831f5fd7a02ad13cef9496fb907d35cbb4f22859fa54c965369a7c2f16a3d06e17a2a4b31b8868f7aa9945019865bd3be32e43ffe8410" },
                { "ne-NP", "7df02f7529df0da5571092b34dbcff8df65d3eb4d17974b219bc61d97d2951c268cb4c00de1b65c735537361a08da4e364cbf470490a87d1e74b262664f83c08" },
                { "nl", "5f9c4b1d8b81636afd6c4260ddf3156ff1d4d45f7999c44996e77f368551ad96c5a6fa5aa36f943e8d5bea9a4f0ac980b36afd49b929f0c033a022d277f89826" },
                { "nn-NO", "7c2c33d4bc85e5e2b9ccd0e5577b1e6436536fada9193f8145bf3a68f376db136b65fbef84b4628c0d05237a881d5b6ab1dc36e7df74d3000eadd708abdc1dd2" },
                { "oc", "b3ffed8739a9ed6e1fa41a51e1e3198c068099deba6b7801126aff373f8103ab57457241312ac3721afcbaf611cd37783a3f6930f6807b0ea2fcc822f9fc30ea" },
                { "pa-IN", "3c9f43918bef28ea2798203916c24a5e82be78c0ec8b6d4a3eca2b1575d1eda214b24d119cf2d653a6be1b7ce2e4c2d505ae9c39f1e3c9bbfd4707d74a99d9f6" },
                { "pl", "93afa88e5d1e65392351391f179ada53bc82cee207e1bca7dfe8c724c5afcf14ca1e259807290e1c316901759b37c72a74afe2f883d45ef991d4602c49aa81c5" },
                { "pt-BR", "0389a4b79402451f836dbdf2c27ff8e7da7074edc601692286055136907e3ded5f65a64ef1888b66b5f9c103f6c7919bbae8c47f3f5f275039dabf2b4a563b46" },
                { "pt-PT", "4caf33c9f031930b13c09a36563b0bba0e47a32eb03c1880a887b40d93c070459778f1e390d1f132bb6b21c23e9cfb9d9208370574129f258b710c8980f6bc8b" },
                { "rm", "9d4a936e6475d86ec05c7496ca8df4e8f37032f8a585cdf3b78102510dfd1a9cdea04b623a938c44e38e546578008fd590041602d666e7b87554f42397b5811d" },
                { "ro", "cb8825c5c3f278341e4b47d275979fa62c5f9e34fc3d8b42444a81a5145b1f2afd662a669ff8cd2629e69ab28915b4d09212cd4f98de524526cd0d5a7280f21a" },
                { "ru", "51884315e14b4e6b6479ff4bc8f4c45af4001d37ebb60b295f1c86a1e0dcd8c7097d10ba710abade3bdaede027d9a37fe75913493c10716ec4213032d0e77f27" },
                { "sat", "c8446f89e5de5bcf15c911a0d58883a6fe566b5749de4599d859fb2b58289a41fc766156c6533ea3023b540d035a4dbb5fb50634690cc55eb35c2b533a13b5a3" },
                { "sc", "a22e79727b9ab886e1d2184406a12a7fa74ee831c95c0fbfc393ad965ed1283292b5128bd1f8ff16cb7105ed4a261849fc7e7cf4ce1ea111395344a2f30f52c7" },
                { "sco", "7833fa15c37670fb1a10dd71a5931fcbba37ee6fccf79cad254336b04a91fd482fecd870dc1f2e6324b4b46591731fadd6cd3dd044d5c320d06e9955d30c0692" },
                { "si", "8e4528f1dafc06e22be58e0372ffe7cbaaa49927116f8277c9480fc3dfdcf022ffb8134834c15fc4c326771fc44235e40283e565492d88824b28900e3d6c548d" },
                { "sk", "f00a82cb7ee978a4d288a05fb1bb1c510a945227d3c07ef383c65edbb35c8ba9dcef89150efea55fd36da6a2387bd3c4e9fb04732f48cb709db88fe3f2e65316" },
                { "skr", "ffe0f294ac6ee45b5ea92260040b775e5558db9f0300b72b31a588feb2fbb0a571cd9b56573696c0a024764c3174cc71276846475650b715bde8778aec33ce01" },
                { "sl", "5cf1974b2c8588f1a212381c0ef66a667dc7db1a84cc6347df371ccda2a2d6f1b5665498fd6501d6acc03edbb94ac8f2dbc8a5af2ed8c956640c015384ef2b43" },
                { "son", "36698aab657025929f5ec05e17d25b9ee65fcc4be5effcead8c50fb6e76952753e331042ee082d99c92ebf55b85c43a656516a7194848058beadd73389fbaa07" },
                { "sq", "e9d49dba954bafa7aa31c11bfbdb4c8b3805d69f4b18fed3f13bc9a9519afe53810c08a9e2172d5411289ddd5c00951ad253fc2d3b20a752a56a0330640285b7" },
                { "sr", "5ebd186953ee11f699f21f651c7e19ce539c649e31c7a4a91deec5339d3e7efc882980191b3159603f223120c040f51de0d1b3854a743c52222dccb011c00b06" },
                { "sv-SE", "dfde11dc753623ac1f5c07825603aa2a8b3d51afbe481ed20a74ddc5be611594f4cf537b31fb0d5c60a3352ec874ee699d01a06098a5bdb6cf922e87afde3f4a" },
                { "szl", "3e5a931cd41f44d50505ea46cc23647dc02afc9dae81cf123afbf70c9890d7554801f164b470aa62d0f0e713840540b6871e6b234cc37550fe50eba78ca22a57" },
                { "ta", "25a3f9eb44e81afabb6488b6b254cb810ba051a1159edf4e095ee8a347e20051a3def473a823725d091f95fb267a9ff5678485088931d07d4949e6c9ac6eec42" },
                { "te", "3e1df9fc2ef48ced971e0999050dc3b11cb669d565e854c38e89b0bd4a59c003dcfbadf59bea80235dbeb470f22ad2e119972cebc697c53da59e2a6c79ac32c7" },
                { "tg", "0ddb0007f3bf2873bfdbd568c6ee63a8375365cff40fd7da2078a47e6e04d7f35b0e2305a900ac15d81b611a81aaef5de30a233501f775cbbfd1e5b24863a2bb" },
                { "th", "4fef0bdf9bf369c6c3a5953ce3c8230d23dfd48f9a93012c667225a5ee1081e11dcb59eb2e74ca7864e202c4f3ae23c2895a02a8f4d56ba5199c4fc7f3e16ea6" },
                { "tl", "7f8d56396099ccbc9a4ba8456f235abdf21039122ee2d552c6e255a417b5168f71a6de506fe08b117a4596cc8f9f594c8ccfd929d261dbd8eeff3d92b1069740" },
                { "tr", "5ee4d931f66b0804e2835462b790e922e3057feae953f2b3746c8b32687a016df8e46a5c42895a37c6dc590117bc37c5de11b3177c4a2ed2384fef146f63e823" },
                { "trs", "3b8b08ca0e80285f8e291fe6cda2b25241d53555edf68cdef108e53a90587c638c4161b8a7a350f139d62bc9427b39e1f3ff509d5d5548eee9d9e1c6eb20cb44" },
                { "uk", "29a20e7a5ca0eec8f2cabfa1e9ee714541c393b0245a4c6d2c4507874e1595a5a819c8213ac836b4d57ccf6f89599f1d4a20395e8fa76490e23ca7f4c61d5619" },
                { "ur", "3a2af853bbf2ad4d34b5356690b28dcfae43179ca27a263b09fb2aa66b6ece5f891c703e687eac4aa408cf12222f28ca5533a471d6f1f707a2053c32e0b28d1f" },
                { "uz", "baf9fe88193b879cc63570bee87d6e7c3adc592216c6d2211ffa97150b1650724ec8061aae8614ef5711ac57b5fe4967dbb2c99e5d8cbc8d0e05c150216e74ea" },
                { "vi", "f1945aaee50fae9d9bdd7a60fc7e38b898a661af0f29fb30f27aabb0752f250991eccf8b4e418a4a08430182908666e7a6ceb929994cabc7019bdb7c3b3d02b7" },
                { "xh", "fccb0d60a47ef385f857340affdee7d4539bd532e4b88bc5539e8ac6c0d14470a6c3478cad9bde705ad3f73a5a796db926050a9178b58af82cdf55ff33f662fb" },
                { "zh-CN", "b5df16e5fd785262b5f275b63d3b9a8bd776fc98645d951c969d5b0b4d7b04af6465a9b9c18b7083493c6b8cfd54ad5a34208c7463e6ecff6cf2eeabfe7e8552" },
                { "zh-TW", "39cb99ba0a7cf12ac7e16ade6ca840ecef3525b40d56190d93f6e9671eee6b01897f3a8da1585f0735701abd7a1c1c26404a4aff243fd7f4517d45e6b3ac4ae8" }
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
