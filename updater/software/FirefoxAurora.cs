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
        private const string currentVersion = "132.0b2";

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
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0b86c1984a8b789559c8e6ae2871b9946f7b9b89fa781b147ba9ad2bd4fd2e1698ca6eb7a3a4304fb569907692dd686378d39f4e78139e2603bd4e1aa2049578" },
                { "af", "8c917fea49d268d9baebe6e26263d746140870c764c6ffaef4311cde89b4782eb4fedf633eab63af9627802887a1a792cc477ced32ae674d4c93f1fb1053712b" },
                { "an", "4063df17b8ef67b05620a70f5d828a79a33da7681a18f27ea9a7d6503c3136fd883991c3ca3554a62d22ee57ca0c5345aa8991a98e8934af8135f34f65e87d13" },
                { "ar", "ff039828d43186fc262d8cb107c33bec7f12d7a42a00234037b26dad93269c2f195ec541d2421fbb29feab91202861197c59c968ca5bbc09fd412beb62459cf4" },
                { "ast", "c80b643a24dc2ac3b256c58eb581ad2dc6bba1739c8e8d1b1bd353fc976e10f255d5caf08611d7e0a924ef12024f645b8256d4cb6d927cd439e8bb9ae76eb669" },
                { "az", "229bca841e5df527cfa4ca0b431c4d07943319dca569ce7fa4c16837a48095f35f925eaf8d4718b39b0a44c5b7dedb096e309027a47f49769f071e6a59ffd3a0" },
                { "be", "143e2f914e9c203e27e9bcec685da62763d15f2b4386b4ad1cb67eb26651373503c7c366efb27485c8ed4d16af84bd98c9e7d20eca8a53f0d8242f3364d1b3c1" },
                { "bg", "11fa117c9b46dcc908b720a7b4d2c62d468e19bfd0b27254a36f84eeec0b9e7bb90780153a6c80bf6cf69e357ca7ec6abc4b903620046241050565f8ca3231a7" },
                { "bn", "7fb51e18b64bfae4661c9fc76da130138246d074d6b72b2165ed748cfea6a88db1420bc2f2da240d818bd5b2ada766842c8966d3d8b9feb135c01e30d98493a4" },
                { "br", "8063d49f45274224a2b10ec65764996ec58eca5f5b07c79c23a02414796243a936dd1748355b6f5eb130de51d5469b775b6888c595b8333dfd595ee7e3dc99c4" },
                { "bs", "495d8d26d5b75fcbda7c8c0fbaaae467b9281473888a39d7a79014404098985d7940d0ee14edb8af980aab4732246215e0b65d5a8d3eeef90f46d431b2d4dfee" },
                { "ca", "0b105385d23467012d7d44e2f3105f8381cd6a56e9276fdb91ae64f39fe4933ca8075f4878da8a174dbae7f4e541cd319e27f88ff8846e4cc10918f06ae1484e" },
                { "cak", "42f300d98f8915f7b9da995efee438d88c21dfcdf318fbbd138eca8f4c21a87f88c452fd4d6515341e43b34b6d36a4eea9adf3f0b23b3f2ea7eae0324a601d6a" },
                { "cs", "47386a866694b2c554817dc045f4b08b562cdb68f60ad803c5733964a4ab172e6f4745f35dba624c751202e29d957672ec1df2b302f52d899cf24c0f2b650dae" },
                { "cy", "747d13e7915f5245bf57cd68e5f3b3ed8c1196a6b1245886957f3a3e9780b71b0fddad19aa379b523e2d8783c9da35505c06ad7b81a96bb6402e4b01a8cfc451" },
                { "da", "a5456031b0cd2231c43f2892975bfca6fae63affac369c248f775f0cee0d7e0d134bc849989a6b9a05e9734d9d586c2aa602a0a2a39bc3ffcb55f78d2ca5ba39" },
                { "de", "94e905274b99bde8fbb323eff7b204263fb3b8c0a31f488b01b5cb63fe7c67b0f4aa08ec464d58a662a42a167666b5524065c05023983b7c078d873add786090" },
                { "dsb", "167ae77621fd259c494855ff0f8b9cc0f883cebf5349340339bb931029b315dfc59fcf5c41f029566fcd88b46da70f9805a0195381eeb16be91badb10f868f35" },
                { "el", "ffec40629a6e8c02024edf3d944b24b29ded7818c6ef309a5916eda107dca93a5c8734e16ab769cbb7982c0944fd30e6ddf3224dbc8431240e80eb112dee2090" },
                { "en-CA", "44034470a7dd0052010c2fd70002ad28dd4d3e79cdd41cd625a9c30c09d69c49b57cd18fe040aec4eaa35ccdbe7d3b50bf4a7ae2ce65163b260d84d954d157ba" },
                { "en-GB", "927ab67f6222f3d2bca073bfdb2b6a1c4a0ab2bcfad6deca9e43ae51af8ff87d6b521d973562da40c307e42466aa27cf4b0b8ee6992c592fa6b1f2c480ae378e" },
                { "en-US", "52239df326d366474782772476a06cc5ac115f59f2eee8b6104179a14f6a86baba3c0f62a21015dc5e76b976344793d1241284b2b141b38281c7339078b21abd" },
                { "eo", "470accaf230e9e39c844505ef11c071f577cee1d63ea1a47c96958fadd0c3018bba1abd6df1b733dcb480c4079fc62496303674a2b6ad631234b5080a30eac44" },
                { "es-AR", "83b8fce2ee0cc026e11c3f8a912d9613d07911934c48e4f122632ec1bd1e1d8855b8fbf25ec9e0dfdb620d3c489c04ac46723b537ced81b12cdf8a25d5c45aeb" },
                { "es-CL", "20ee4c440d7bcbb65eebd9b923253a1aab27c5450361145c7dd48b0ed1da99b41a1c827cd5e20d901a1f501d3311d26493d081946c13b96d6940b4c529e86da4" },
                { "es-ES", "936a78f4682853ca70c470234ccffe43a48a9467223671a8dc9c533e274bd2d213f106d666fe05d2c3687b61e2bc1a4686b69af774b44c850453f166c135bb4f" },
                { "es-MX", "20ee90afab7ba855c855511972b44c202c4d24c276396ebc6c8aebb99ceeb9debbe87c27abb7e6d2abe5b873d4eae96ae9ed3b3e71603823bdf0fca84628be3a" },
                { "et", "893fd4a3423869aa99af5fb05df67baeec074c1ffc51729fd39f4f470dc5f636bcc877087943e450dab7762c7ec8383336acbc2e916b9424fe55f0d7429e6c42" },
                { "eu", "560a5d3c561e42da6887650b95a1b3050efd7afb6d5a6e02d6937634dce54ac70e135780796cddf85a6d2af5ad2c928e09659381c59e2a44377377dc4ee313ec" },
                { "fa", "f0e169d229511c4ea560fdb843190582eba9f873211ef198a4c207d0df36cb937d689508bb1764c0f75059a7b71e7674b79624604bbbf1d49eaf2a397cf3ec9f" },
                { "ff", "ec886953d1296d53239cb01cd608652348516808f73b55836969f2fd45327e51bfa35305b684a62ead7656ffaac0a4db0d6c75dc7e5181ed7011688ac4e77b99" },
                { "fi", "c2a46783921a87b991be3bdf767ba05668258b30e0392e404d52c52e81fc3cacc158298daffe926c673139dca521e9deb0980919afc94d7265c9355be8610c81" },
                { "fr", "89fb208eb3a7da366f1ccc797ae991dc2da32faa62ad176f0a44bdf061c11cafbb2149f0657a8b7748af3a2202c2b1f69b582da63c0f25b87c62271b6b4dd706" },
                { "fur", "c57997024f962d9642436708adb2868c68121c3c0bf896de638c71102061f08926935387412a0d797ae4661cba11a56540d01b0c029c2a390b7b3f28ae21e103" },
                { "fy-NL", "8a397e490108f9b4ed42ca798b7174f4882b7554b74df3419575a615a65cdf654f2112897c6b8c12c3fb63dcdb0c9c72ad37210b91222712092881a0c70190b6" },
                { "ga-IE", "1ada2974d376996ffcaf1f48ece3b377243d9ec03567ec0b37e6747e72e7c1ac38976d88a8c97eb5c9cff6d6c6e25ef430fcfaa7ffe9288e2408311581411368" },
                { "gd", "b3050ddf5384d57a940291fb69082070e2965355030e6440354813a7085e7c1a73b147c6fd398e23aa540716c22c02fd428150b0ad63e17b25b5324cd31d81e4" },
                { "gl", "e1e6eee35bd41fddf6d5b0a705eeeee167e4dda8d4bd0a327a94390e43d6e42460d448ceb83d78848339e25d125a317201aceda435864b38ba8c061d3066d25e" },
                { "gn", "0ceb8909169c803b07b17e804d40ce08b9c178da0e635e6a8a5cf3e4803269d3cf6aa811f8cd39fd445381163efcc675b75438bec2b45ca0081868c1cd74bc17" },
                { "gu-IN", "f920966df92a5b8d329580ae466227b42eaa8abed0a3daf2b4fe88ac358c0b32adc964eb2a73933645d19a9ed1c532aeaa273920a8e844b9ce26ef6bf26ce273" },
                { "he", "23ae647f8a8f67b960239f2894eafecb0d03474e23e85479fc53a78ce2b61d1c9ff3b583321e08c11cfd681249937ca730a1a4ee81abc1a7327609c0c7a1d6bf" },
                { "hi-IN", "c88648d05d824fd5afa15b808a6c5e753c1ac82552fd2ba141e9b4749c7e37473456f3e9a6c0ff17de8d2c88215004260c97fcf020900c6c633e008b3101f5ee" },
                { "hr", "7c4755feb10d3fcfd6eba74bbb4609933e1b1d09945248b3bf6fbb1a300b28e01a729dac62759c8d41e24ea1ea2b5a1d12397980cb9ca72d42b7651c49cbee97" },
                { "hsb", "99b5c38dfd69cc463849ae0a58cbffe56d8acafa3aa100489f63c6e3d2a75d17cd6666d709ac83f2e294526d6c9a41faa5c8a0735e235e1dbf66fdc1a83a3220" },
                { "hu", "4d702faca03ce427013982ee6de95446caa656e41d358d50fe264f73867f5f8c7a5d7ac36845ff91a2c76886a92dead1b1caba63ed6ce3b12ff38b5b040e5c7d" },
                { "hy-AM", "968e27ab1e372cc4a35b68e38e3c8efd6440c7e67fb1c5eb3d4ddef5ceca1925a0aaa6e01fa833e152c67459b7fe15437ac1c603d861f035bd54b228b986fa7e" },
                { "ia", "d5829c032f8ff5f118cd4651fb373090e0cd3dca789bf4d3da3d5f182b3c7ac71527697b7c664d6492f055cafd02215bb9c7e69b902a385a20cc46e3460ea287" },
                { "id", "37d92161163e0f88f84790b3c582724526a60886928ddcff517f522bb7639905a051ae971a796a191f5a5797cf994473ba8fcc798f40ee8a342631e3a9afcef4" },
                { "is", "7fad572336b61ebdc893def0725c258e1f0003dc5c3c8f67b2f5c8757be2aa94a45ce70355da2bae0613aed3690e2985c0f8593112d705e89e0e948880220835" },
                { "it", "f75fb561331e70f842112760ebd02fb36ecfcfbdc913668e0c17e2af7cd50159c6a1ec3495bb25d5379464ef1b8b4a782ac8a2fd7e66210f15c50dbf34ab3558" },
                { "ja", "45780079f9ed1a8025b8847c0c7bc9f3dbf49d48b41529715545cc4e10b530d2a0ac77a8832238790fd24e74be62d10979a29d1b3f13bece9de398d865628e05" },
                { "ka", "7d781cf5d1671da5db5c24fbfc12808e1ea39a72f09cadd5a5ac4798e8db20c22a75d0b0c67f7c0d60386b8e54b23051d9fe9b3d8cb8dc91afaa8d10a15bf03f" },
                { "kab", "06ab51594476cf036d312e337600560e027038eda4aa5b1bea8476c2acc9cd3be4dfe558c33675de0f543f2875e62354740801cfaaf26ab8c74686e075dfdc94" },
                { "kk", "ffa5c42860912efe025873448bc62b3a53dc46c3eef285020f1344fd8aace952a10588bc1269dc0d99e7f4355de3c757ad497a1be9fed58460a2259f6a6fc99d" },
                { "km", "75979cd145de8e0eb77af616abdb9a50fa8326ba09fddf89b4e64e1a5ac410f2d5e79fc60e5282de01bf204572f83665451c2ceddfad8ae5170efda7a08298fa" },
                { "kn", "4df13eaa5a72d84030325e067b0143e4c02e8336b765ef38179fa4cdc755461cc80f4d3840f3d36d05f0d986aa56a9c7c0e8ee548f870e15c7da33cb436ed258" },
                { "ko", "da76b601ea549dd802e117d949fb03e4b910a7cd9f9b6230aaab9468ed32e38d474eca5343f35e4751dd219ad3e4cd1d2afd10bfb97f2665cd70bf6708991239" },
                { "lij", "72167e787e5f934c01f0d63618dc9f047b0d44477933abcf626e627b7674af10ee6c7f7c74967dd9b48b9f8719dd2799601391b4997e0d3d4ea8d95b25a36ff1" },
                { "lt", "4ba4c5818e96926187fe0b100c20a5f8588ab38f18a6540295905506107eb2230b64d98cf139e4422039783f2afe1c0f4aa684bdf0fdc807dda51a882dee1003" },
                { "lv", "82ea9cbfc6dd1e7db1506450a82b83d0f362f735cad8ec179407425cd63b06c5545e330c062967e9223c21ea8d38ae31d8aec56706c16956aedf6c36817407ce" },
                { "mk", "30f0f632f6edd2d8ca450997246faf65bfec67a04ba31130dded1bb2c63d4f5c12093b1f9d3baac51d9ac303948c281ace96c13d5f1829afa3807ccc697c76e9" },
                { "mr", "eb516a576092f4983bc111400535afb11f51bf1c386496f295ebbd06aec645fed6f53285267e6726129d68515ea2a281d3a48d31e65062e0e3be0a76220d1218" },
                { "ms", "5bf227ed0b43201ad65976956c6ee9242fb151ce26b6bd2a5ccb5178d7335cf20a1c922919cf3d73abb5b7382cec1c3ccb81ef04e4d0e51e030ae38c86408dcf" },
                { "my", "fce6c79461b15544b16ef688b830ca6c4d28c0845ff5c9a5f78567af530461b77b847c678d7fd0740c44788f9aee556e947814973391732a985c22ea217f88c0" },
                { "nb-NO", "9c4feb9bb4a593ba14a87dba0978595c0781188aecf0404666ae8209a59c2e073a5d48a74492f9f5150f9ce6f046e644d4949f511ae475779459f49962e79a64" },
                { "ne-NP", "69c9f48178e23aab8412dda33e05b67eaa05d92523c65a8b4a35bb2ea78bbc766dd0e3c8ab238c59d86641d4a279374fcbff09555fe2bf68dd2cb4d96690517e" },
                { "nl", "0e081ea5affae350b92ed5c2785d4e2a6a48cb91fd60080d8f6dea37a550e61dc505dced90eaa132156fd07d7ec25638025e25ebc28e481092aee99bad88cf32" },
                { "nn-NO", "7e832c883bcd2d5087c63f84f4d997f944fcca2dfe0337f6f13b988fab9f6c5321481696c0756ac43bd73704c619bf9d0500f1f25292bf98de2ce52ccfd99659" },
                { "oc", "889c8d9a770b7481340636f57fc17735eaa280e9affe4121ad732eb1b94a7c6a09a42536e12288dcc3cc0522f5b29d8d0358f2108d862a7529b888d0cd98053c" },
                { "pa-IN", "d863ff578d7ed7b1ae4649b2ebb5fdb1a25b5b38cf6f34c0c8e1a73865a064f3ff19c004fb2d972c40a6f9fb80c59f2221b4215ae1cbc97531ac1b2b121b5e88" },
                { "pl", "fcfe9ff92ea0eb8b633c471b13647105ee66039a0d60669efe7a85e4a8d738e6326e78fac5eeff3cba84ce7506c4ca0956822c1e2512b1648c7b057f6f70713c" },
                { "pt-BR", "30708dafbfdf6482be9e9d5df9496846ccda07b096703b58e1aedc6c6f58babbd7ee94f62d1c8eda24c946d714839b73368f3ef851079b0fbb1a88733662b785" },
                { "pt-PT", "8d9be1976bfc696c2831091a7d5020bf95be146266a616222e8f94bdcf0d0ae76a809a4f39688fd4125008cef935c122b47493e96f618dc963a1ed7d873461fc" },
                { "rm", "128d6c300444d066724c7caf32b5946131728c061249ff441cb37d578f594675e30143f6ea3e8e99bf32c50323424e90dda59bdd98241f9989411a97a7969ab9" },
                { "ro", "b54d335247fa19d5a92258ef90f2d244369095d08c74c0a5abf635c3e357ea3738d945e2cfb5fef46b17668b69bcb32498aee5a1ead506761da774b46bb8ba0c" },
                { "ru", "06dba61e7bbf1ef861ee52601504c211e78aebc2e024daf4527c7b0e5a2b3ebd0e58773b6e47bc3abead7f59dfcce6bd0fede570da5bd6ccdb2bac94f3ab3605" },
                { "sat", "60fb17c19e8a95a3bdf0cadf31a1f8552307d15e0372f3d60610de0749427cba53698da843203c824d8f815694ba2d210f6fd887b0e6f86f79004feca9cabc7d" },
                { "sc", "988e52aa6623eba0f44c23853586b982a0c8ae49307085e513756c91792e9780de1c1876f4fd27080f4fcdee079addb92b2041cc82d759b0241a1c4416e7f503" },
                { "sco", "868af254768adcb6f825b9bb677ef62e489c9914f41f2660e8d5b4ee969196faaf46f6a5522b7eea8875096b84a52578aa93002e2744ce8427c00a8794e416f4" },
                { "si", "9d4b7bb635b487f81db0d1943e5ac17f2f26f17139c8256d2384f7849db86426fa50a619fba933f96641f3be07e8194f1f2ac936fcc5c6e3d9109505618fe331" },
                { "sk", "59f1ba9e5f672d380aa33bcc2a49736fb37b17efcec3bf2e3987874c1c0152768fea99e67f991ffb510359100aa8faaf03fcae917b83c89596b3c864f450403b" },
                { "skr", "397ac587416ff4a52d967d7fc3c3ae2ba2daa18e0bbb001f832e31b4b9a18d49ecc2c5cc309f91c5b36c74fc9f89a1230dc532dc6ea038f52e140cb39d96ff38" },
                { "sl", "33b6603e0dba7a8b07b46071540e6fee31b130e0ef1986631af169a88959d47d9d23c3a40fcb752f89e40dd1a5b98044352ee64a5df3826f98bfffb9356b90ec" },
                { "son", "0a34f87df5144158a11661919a219942d3cb0bb0ffe0f7c3ffe742c967a96d48a3114b8044ade3b0f14c53fcb72ce79bae98e2fc1f0afe4c4a0feed87bb2a53a" },
                { "sq", "bf4ec8499b98db71b27daebb52d643afdffa0f59676b28bb1d7c8bf688b0b10354cb315eaa1fd63f69c06172e5db896bcda3fd0b741b4d2bc1054e2f6ce16533" },
                { "sr", "d8d502cd7e0f495cc517b11e0038cd30db19e383e9657f5cdafc617c37960f0a0921e754b805e5f2963a8b2497f8af24415e0c63f02c144e7f2231cf604622d6" },
                { "sv-SE", "cab2c6208a4a8028eff51cf4a5e05d2771b5342f090a7fb293fa75ba99fcc21f68c59986fbacc9bd30ee0f8702a380dc36ada4fe3fc8eca7eb93bb70db6e024d" },
                { "szl", "5887a409559b343da84612ee3da4414288764916df4ea13c9eb4006a52a070796e6cada955b203f2dad2da5ee3bffea57444744a48814f8609c819a67b18294f" },
                { "ta", "82caf8fad80d40df39652ec9ac9f3866224738f98d9925af566f4e5305b69eb3a877df1b8cff532d8e3c54ebcbadc4a0015a813242a1faef60c434e3314d8bcb" },
                { "te", "aeaf7d6ddd7ae48f2ee4dfa6cc6c4425e71534f0322000652ae43e9d4a0b9731c10063ba290f34ff3353dab5ff3ea9f435fca24fc0d2df275265fa00d6c4b5fd" },
                { "tg", "d9dcc76890f5e2ba289e9e236c4bd2e9fbd70185774f4cc238850d05b51524a8b4ee7010efdda9bcfef87d92e78c4f16cebc2cd41d16cdec7dc16d3961c51a3d" },
                { "th", "e79f47331eabaa66a6d834f516dff19af35ad52c4d89578c5cffd3d80ed5ae666cea039ae2618c1bf112847f4b67596e443dfa2225d7bc7fd27f0bcc5af55155" },
                { "tl", "9c34a1ebe09875f78ccc058607ff26f65a45257af52d5ddb86bd42750c48c3690d168d31d4eac91ae9e0331881aa09025c8959d9898d508f099d030dad1aeb7b" },
                { "tr", "8339c41b0d9db3bdddf45d9b3cd6e57203edb03ee8e9e0f89ff92698ccafb1e94e31ea6955203cafdf0570f7fbec78da741131c5a9e15a443d568c24ffaef835" },
                { "trs", "eda3e019701820604efff90111b0ab9ed01fa393fd0dc5b7017d24203f7707724b32785e37c75f88a2833fccc9202f66abdbb8d5edfe9e1a232c5dafd730161c" },
                { "uk", "08421e26e3483ad1c836e541b53dba7974fa16de61a0f527c63f8f0ec1e15eb1d8c0d15a31d31bd605c8d3b1d866f51a92103fcf49327276655479a406cf9911" },
                { "ur", "358785bca8f1faae20d2d8797bf8c5a4180f35a0f8c649881619b4d1f0126b2cd288c950e3040f2a90ebc4905d4e31e92011524a43da31348ef3652586fa8551" },
                { "uz", "d28277dd661e8d49509beaf17562cec4d64e4e18555803d51baedd17c8338e582c295f84d36e63336a89841787d9a4ae6546376067d71301bf22d66d1d4ff3df" },
                { "vi", "dfce0149968597f3c479ab714811337a7a71074836e622cc49059924835dcbc1b830b2850ee740b77d986cdf6343fb54223c3cc7080707551d3ed2b646674026" },
                { "xh", "7a24a2a1b80722991812b1695e99e65436993979ee3dd300e0ef705f532c279138dc8e460ad3cc81ea9b2b9a73d4d8e14f8bb759d48a1d72ab6516783f0c1ae5" },
                { "zh-CN", "5d91ab51a5ca6c44fd66093184a77df64cff71451e892485b3dfa142a9d4ad300f221d55bce846c046d35629f525d0b8392791a3b170d1ef137c72aec5aa7203" },
                { "zh-TW", "11c09281dfcf3874c8620abb08e9a1ca78d41f67c1a3db2b3ba52225edf8d8b8fe43747e718ed0ff3659794cd0262ffc72ff31cba5cdb4083c6340f2e4df642e" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "85ca333ae8584fe42ddda16172125c42e03c37c9c59f6823aa730516c6be0de601501928ba00307331069edbe8abf874b43f3e4600090df5062d6107802a6b9e" },
                { "af", "fe747d653d664131f70e2b1ea568f39cc2deb666329b92276e32da3266d608ef8e8b5cd29b2e7d70d9b670c1afbbfa983955389e42b6b40fad6ca040a595a23b" },
                { "an", "ba1ecbac17576c17e7c6867c8107f1fb58907443300be783f1b6d19632b94ee5523e1e5df5a330616a2b2455ba86bb23a7140ff626e87f79cb6c8ed477e30860" },
                { "ar", "3d6bc081b8177e15f6502679837045f1c0d311f3e5a73ac4abef69bd6f0d18ac53c7ec8675ae9c7e545e5ae6b35da91769ba15ec98c177f74b684d1fc8deb28b" },
                { "ast", "4ed3fe9111936b4d8fbb11480623921c5a92b032aba26b5bf3d1552bb9b59686738063e73351f31ce1d574e5f2087ea67399e030b7cd21ad5e0420c02a4d7770" },
                { "az", "4f554a64106a2b4ea98014776a6aeb4310ee24c2c9fad08a241af1d7124519481305b5aecdb3e1435a5f54a169ff7a9868edbf1f1533bb88587f978be4bde0ee" },
                { "be", "9a2dd00e9a4f43a7e482d6182f4ae4a654d2ba12a1fc35f46c1c56edb1d5ea0a445a73632f1f4c1f142fcd323bde4943304eec9417bab96d6192bde8dba0c034" },
                { "bg", "8a85384dd8d6158a2a1d10a3fc1e63eb77cf9b12bd8f21e60ea2d7f1bb5493ecd179dbbe486756b8c728e0841c63fbaa1fe0a4282d297216b57ecdac50788643" },
                { "bn", "37111c40640db33b2193bdb6547faca511e67d826531dcff8cac963a5078bfe928b9c17662f6674b4a1f9a28cedd9596011fcae810fa757cd9b4e5681449bfbf" },
                { "br", "ab30a8ef9f8b62d0ccefb62031628fff4ef06ebcc1a714cdba37d5cc3e1c37466f29610dc2c4f1a30b2c686b351b66377ccb365de402086a010f62ea73a5b61d" },
                { "bs", "d85a41cb8ec5b219334a70a464adc28c5774d77d13037b41fcd1b1fbc36eb66ac91e5da8f8ef7dcc85980650b8f4eb875d541587be35e413275a57b3ba27582b" },
                { "ca", "eb073b525cf2f637a151207dd8c326fbf61e0a0dfe581a99c5257a418593891806e63ea488aea54a714f0a73addf4fab54facf7df436f27937a6991a9f20d8dc" },
                { "cak", "5b38b3a0e7b65f57bd7128c346427863311dccb611338607bf017bd678bb8e27c8c364bc7081962859e37b32b5984f2453c0a257fbff2ccb36cb08ce34131d3b" },
                { "cs", "575fbacc8b59b9b189d841023554a0b13131a9dd9b28784b3eb1a4bb9b06fb96cc795b21b4cb32910defabbdd048a8caf66b5b5bbd526cf7e3407f7bafcae7c3" },
                { "cy", "c0b9692a813bc82c0b416a380d72373e8d30bbaef06473e12b12a3ec173f23fc3eedb70f38f84ae529a744f7ba6bd4786ce9752e1e20c7f8b24fbf592a16be1e" },
                { "da", "b3d29c3a768fb4e63ac71937a0c0f72f4fbbde62fd6ec2605f20b35ebdaef91b6978f066834b321e7c1decb71392c0b434184a5dddb096a20e70d581bf263ed0" },
                { "de", "68ee74641f3ccd4a832c52c0b4ded3ebb7df08911dc6b053e348360f85e69a7cde4eee24a2debea03fc47494c22c765b90d5174c7d1bac96cd6b7cc8b881c9cd" },
                { "dsb", "228cee4d0f4ccee0238fc6909c170ab83589b4c222717dbe0b9cae21d2013c0e414e16831d1ea2dc7f1a6e7954fb8de87c4f1bedebf64d780c84c893043cfe6f" },
                { "el", "365bfee7be353e89ebadb35f48e5d1412302bc06ccbc7e3e68afe8b59e454a0c9edc3896dcf7fffa4a72ba6b01619fe2f3e59eafafc8b6c236e55f261cedf013" },
                { "en-CA", "54f9cb29c9ea8e5f17b2cdc44fcda6f7fd7818fda29e0941bcda5933b68c6d43ac65b86624acac4916aa38e0c213e85e8b2d63f3416b55ac811a10661552c1d4" },
                { "en-GB", "fe818cc8151584501716c1722b75c88f8f9cc6d44a8aa6a673f03a550fba864d5d42310ac5fc96130cfedaefbf71e3784456f41a3c1c9cff802c4c6a552644dd" },
                { "en-US", "858d8b6279396127aac447e200dea5fe4913026cadcb6203402475254171d64e05d602e6dc7c076d0fbc293aacce52f25df6a9939013174ba32ae04f8b2d7eee" },
                { "eo", "8248235e415de490282577e46451f42d4ad2ae5ca5967396442b68e118e3030577b31131195c2f8997ce1401f2ded9c8d4d110582722b916ee16b59b9589342d" },
                { "es-AR", "9a660d40db9b73a88bb0d1cf671259f5dbeabdaadbbfa4fbd3f71ecbfe98f5369d56ed743873ff8b53d31da663597d8d3de4965aa501b7e32c1056abd7948865" },
                { "es-CL", "61b33fb556caa5da9330112af0252802ba45c829c8097a4fad48f7e56fc17fa21874aa921a078ab717e18ed11e623ac2e376107d85f7de276da6595ada90f748" },
                { "es-ES", "70b5b1bab48a51b98e7ee837519c04cc71ee45627e058e7e44408e7698107cbd4fcf7fc69c60c35ebaf0dd985de0ea4f6c18b52c25fd873f908642ea1c9e6afe" },
                { "es-MX", "4ee637f66c8dc719a20bf4bbc4a815788fb46c65d262edf28e805a372e66b5c57f2d877f56f9d5a4c120fe501ff1f2179a504dbc7c95226ac48020a17fce72d9" },
                { "et", "7716e2e779c5470b3044143933b0c06f2699733b27560b43575258abbecfb04579579e7983619a71d01945f919b001ea696e32e5c6079d31767a416a65f4463a" },
                { "eu", "48f271280d8c71df9ff64adee2456d6d9a3ff64bb33334ad24e8a27c7c3eec3443a5aa1ed59f72909d90ad3afa129f73a1465df74310f097e6fdd3f581ad1d8f" },
                { "fa", "9e6b78c2f2334f441ceb07898d3d0ba9bdd8fcc1b26ab28c613e4e9af334f4882c2947388c71138a07956e726cb6ab901a7fe1a0ed048e139df412b89a8a63cc" },
                { "ff", "3ad9efcd0a93f26cadb3ad54955b9ce8bc4422a5b0913e9ffd0139d0eb7a25defd2a3bb4de7df4b58aa67c9910500a9caf10d6476dee72236f47e1729230aa8e" },
                { "fi", "6567244f130f12fad2de0ba5faa0f2d8101c9be190c5ad26eb9c6fe704c30c182983cdce80a80adb3e28312a073e24a12dc93360cd22216d4051e5bdd76a51b3" },
                { "fr", "5139ad7c4267be561b7905d5dc6dcebe995210af070b12573d5195741f439e8ef5c9505a5ab8b5ce24aa456c308aee14b52efddf62918a36bc4e9ffa4163ba79" },
                { "fur", "05bfc386e89a5a82e3aa99d6bb5f0b2987cc6bc0d8bc97480b0730c29aa507c423bb65dda04b18bb12ecafe9355d61cbabe37f714c3f331d184ea3bb5ca7d43f" },
                { "fy-NL", "2120b323582d7131d473f863892347abedd8badb93179408ae9b9c813bd7649c1e11c436977dda6312c211facad832541a9994ace1827558c1f5e63648ab8793" },
                { "ga-IE", "d884e6b5994b88e32f0371c415d9c1065af6ab5c4a695247bbdc68b884ac4a3de033749ee2c0b4387e2a2d8149c476fb16dd75abc3a8d29fdcada04c5eef1895" },
                { "gd", "c69379eea2517d3a702ef0e1c77b662019e4742aa34b2472171d341640ea0b19718e33a87e12ebfb878cee268de2f4cb0eda3225fe44f4b1e3beb8db0d4e399a" },
                { "gl", "d959fee3cbd9184aee473c2ef0bef5cca7a8927dc99567157c99088e097e06d81d6218e3f5c2feb12425bcd178510fbf0898ec16e3f697b76b6637bc76acf3e6" },
                { "gn", "65f8b59859efb4ca2cfe1017705a74b6e521e1649efe22de974cafeeb23db8476d9c5efca72c130cc1b3d565a545d7192c34c7828e9502aa6472155475d0786c" },
                { "gu-IN", "5b34db2b02a7822c2c6b1c7c52800d00936e6c8b22f91b6976c901e710f0ecabae7a3f9fdb57d14d05ad662ea71ab7248abcc1731838bc3726dc9cc777e9e203" },
                { "he", "7c2bafdfb88677ccc8c0ea174f0dfd6cbfe136e6013c0d0cd9dabc14047ec4c22693fb81bcaf695169f5702e91f841674c4917d725b073c91b2cf37d29f1fffc" },
                { "hi-IN", "650c4c7e0deb98c6f87feaa58dad960c8a52b75c63b416bb1b493df5c15c2ef1612066bfaa65e96cc28ae0858a3cc4d3c289d709b85da17b2599197ac1740e60" },
                { "hr", "213da9ee060c3e2e446686b49c4c89937072a35bf7c403f89124cdf57340d3bd66c1d7526934a744210855d3b076a03431e6f44817e9001380b7430289058fdc" },
                { "hsb", "88f614bfbdcde664f3f7c016883b0b29bf1b0152ef0233d430ca8fdda915ae71ab1bfbe3a41a28b66818df9623297726eab4ffb9c162756d0259e3e7251379bd" },
                { "hu", "a3c5ad9bb92fce478c5aebb45b8c3a186fff414fe7985be001ae1e0c2a3ae4c0df180fbc691348b170955849fb2d522b4eaeee03d407bfb9d27be6afeb75d2bf" },
                { "hy-AM", "7bc25831c48f413670c3e1b05df556a78c4b5f01b821ab7bf216c140305d59fe4888827ed2e05e770badf998317400881fcaca5e4cfb308c1f02e3a516f6a00d" },
                { "ia", "2939f38b35c14c7b537661bd1fa4ea33cc4b0a83e436b98f44f293da4171f5ef87247d48eab422235071c55aca56dc357b14330b55e3610bb9450596d0a5d85c" },
                { "id", "d578ca8134ebcac3e7f26029ed07d91400527b6d2f5ff1f294f1b0a3fb9656a9b6394d0df268bb7bf812a12999ceda60ed5e1a7a0b20f9177682fe7f0471769e" },
                { "is", "c32981b585ab97b429c741c5c4d832220c93870174625290cd3289d6cbfa056bd5ecea44447289364b86e1e7a0452f1d50f389b823fa2bd3457bb8de883d6582" },
                { "it", "e61f2357ce6adaf152d0c733ee8c8698573e617ce7af31595c456bb7ad31a0ca66cb44b818574840f6d3162a4f766559ce4e0bc44d9ac605e7efe67ef56b515e" },
                { "ja", "0c657e1e5694233e8b3b4f70ff4d06af755e9a1d902176168358f84c8feb63e6619e87cb3419c1782abfe7a131ff36d9051942f8f0ae810740791b121dddd9d9" },
                { "ka", "680d4b2e41b19746d765cc68008ce136ed61268de3eccb5d38fa2370335a503cd1f38de3232afdcd3fa42ca5589ceb3de7595d928f38d2d6e23346df34e25d50" },
                { "kab", "ea477c27f7b411ef7937fae6033b1dc5da03525f5b9c2d2debd0b695f0756027f070dd7ba1e6c3ec1d7c4d5430c9e6bc618e3cbfb715a96b8116c10d73487708" },
                { "kk", "aad24f53f98598cbbc0a5534838050524b00fc0df2d2119b5985bb3c32e9b3f58493bb61f1439cf1d98be7e70734b51b3f3f8352c9f28c6ce881eba539269b44" },
                { "km", "9215c12798fb804d5b5c9985902a8fc285ead188d53a7ed8897b076e6c4940cb1652fa378c6074954881745d472408c45a6cb596c2530e3963a69c9967a1816f" },
                { "kn", "0a8a453956d5cc0dfd21788e67ac00c2ee6cc5b68064e878c661033c61af5649cbf1c31b626c294401f2794b58e498515340d5982bfc55607fcc55c4310ace71" },
                { "ko", "5d5cc98a93ec9379910a3ccdb46103e8766dcc5aa25446290ae08affc3d6e8d9ead94dbedc2f0cda0595bed04d0e1981a69e650f75b19fbeb96552cc818dcb46" },
                { "lij", "911d0132ad82f6aac12d2f7a59d8bf75a3a3aee42b563f380193b768fdc77233c1cccdf5392613e87eddeaaec404aae963ec705a6771f5ea9dc4986e76e44679" },
                { "lt", "e021224e1d855dd876778b0e559bc1866beacb876d82553fa854c91556577531ac47f234405d1cb949e4d9dc81fddd3b19f1d04c75b6308c062cd97f1dc938c3" },
                { "lv", "2bd11437c18be916302e160d94792bf7be38336f44e4f5ed59a1eae9fc572551d858ae3a6939d8cb65fa3db87c328fbd184a5e9a623784921b6c1aeb97b54802" },
                { "mk", "6af5db1682214cc069c68635c9caa05cf365a6a981e17d2e3c6b055e88b76067ebb1ade9f686c933769a64e4db6609e36bc5f910bab9140099cff2a798a2cc11" },
                { "mr", "b2f514e4e4d54088e8cb995eb7b033da0db3959e553dbc864e1120df737d538f1ec1f235d0f4b2e653c5dc3d14adf06b8ed5d64f0dd85bc48d7885ed496230ca" },
                { "ms", "07ff75b098ffd797a94cecd7d54fd40268527e2cd9990833ed085b77baf1142a8cf6f59101536195fce903f9346145b2368caa2958ee2e31b9aefc7f39f8a171" },
                { "my", "fa1cc6d3b4f66223ebc2dda082e9e182509043e637b5e5e8e93bf86b03aa898cfcbe8371cfac925e20e95e66e45edae4d65efd3e236a24c4e51d969e5bb7fd9b" },
                { "nb-NO", "0bb14fb45eafdfcc86c471ae938933127ec6bea5e7b84017caf9478325dca1119f3b1fb27c84bbfb2fcfe4e631a4d63bf74707204efdd10614d49b4427dc1e59" },
                { "ne-NP", "d48bb3b3cde833beb5d321a0074c11cad8967c9fadd22efcda010687a4e20e34815c6b533a91f2402c51483e6270ab06fafab338c6840e1103192b24cc16923d" },
                { "nl", "bf0c8f54d9df46b1d1667c82dc6f496a32889ae901a7303096eea40899f10bbd5a7d44b5c1f4ad45211769b50c6a4aa5bff6694c9806ec28f603ec87e729ec94" },
                { "nn-NO", "5e2c986cc384de4662086728c7299a74e709501f8c6593363f8871a761c0120ecffda06d1b766c9c75b2583c6cf7430f17eb8b4c4ef63afdb8925b767b770ccc" },
                { "oc", "f453eb3d777a953984729178dd5609efd363404d6fddf842219d48fcc72b06584c7b2c90259f2547146ca9ecc4e3cb3f03c5258627dc058cc3bc3a6b8d8c95fe" },
                { "pa-IN", "8d9a883bbcd7a58093dac4715d902b5d9d091cb39a23682d7efde4b00de3c339e5e0f741d6e7fe7526ae21d468ceb515f1f98c741c11a5af6fe77fd689539b62" },
                { "pl", "3237e8d8ea0ee6f7edbe1eaf9c500acdeeefb5967fb8471977b5295a367612b142ea4b31b1e23b8e4edf073be03cb21c7252b383fcb2557145bf3f6c68c6a68b" },
                { "pt-BR", "9e6aa5f709fbcd4760847f7a6a65137a222360c7a84de6b94d3b8904f268fffeeec4e2bf0d752e88a6357a56979477f0f35a398ff126d2db3f372795b5334e56" },
                { "pt-PT", "6d9e0334b39182425536fa00c8e75f0374f47bf743fb4f78bea6edeb81dd8f84597492b1413d4c6c24011f2dc0b6f44b66101d0f206e0169dcf031810f22f447" },
                { "rm", "06b626f34c03cc71487b4b8831de5b88d7366cdf63fb45756e8b23e2aff59ad9dab00a1d3a8b95c1d13a5140690b66bbc2eab333a9d82515b138f67b2d4ade82" },
                { "ro", "2962d8b24f9f2622315ab3424bb4714da1c274e5435a07ca2096178e6c59583b925309da68985c51b9aacb7e82af11759489d270498f0384d134b3c05361eec0" },
                { "ru", "c071a102199fe1f56179d8c676092c6e7660a59b313966dae550a997e209f12ea177acbe92848aa3fab69f86eb2db6c19cb96d5c278b11d3917eb67e82b238a5" },
                { "sat", "c74b21136e52c32742dfdec9cb9023ebd22c61751f29439905eff390ae69e99187322bfda455c7a705eb179024a525d73ba3f237593bf9cbb48c3a6198553b53" },
                { "sc", "9f7d9f4cd964418cfba451a04d59c5b8bdbc3be2ee27adf1a48080b7711e8e4b7bb1c8fc499f9a1decd80682eb1e1f46d03c74eeb3751c27f5b67e64db5811c3" },
                { "sco", "3e249e3b838777e5a25d1727003043b9161b9a40641c70b191ffc5a0695e4087d492f731dc8719cbe0bb157a68695781699c904b9c20d250083455d4540c547f" },
                { "si", "e6e591b8eb4f7699382b78ce6d9a34d71c94128211da1e9db8fd5f68787b56565c16ba34dd51ebfd18900defa115a594510f4277d483d26e91fce2486aeaa7bf" },
                { "sk", "8d54f9bf52465a56a06e98885617aea67fd611096715e373207922e9b07f098daf9afd58a7696bdb3307416e5f68439a1316778454013850249a50958c7ba5c0" },
                { "skr", "9465bca3c626e8449c6f56f6885cf02cb073e1d11da8b32b64d2d552daed71601778eb1330ad3537de4bc928b78445dc70c5c0a9db838303675f8aa70dace438" },
                { "sl", "5adbd12ff3eea258c3ea1860080bbbca38889728acebc9bf47d3c3b3b19330c56105e45ff5a87e493b5367e9f769f7c584413bced99c082c6e56fef8016a28b7" },
                { "son", "2d70f3f401948a6b406a612663d018af29ec4384693d8d576914786ace99e835fedb707476eb12d54a2b21185678d75ea81d8cb63df3dcf05f099c79ae6b5529" },
                { "sq", "6d0decf20ae1753d2e11a477a49e16752bd0a66d1daa107e5eb3b81f80ef48d0311d782e4c2c602800178043e5c741d91039689fe9155af5ee856303e57307d4" },
                { "sr", "c16f454af7bf84cf3714fa9249ef7f0bf5c72e7f1e1226f227fefee0e0fe2c77b5554625f9b74cf54613b820ecb98fb65699e3e13aa8b963fed38f84b719360f" },
                { "sv-SE", "fb40e6af69e0c4612cfd798576e81e1b418d351e9319847019e6597d775d852afe91f2a1fdb93fd24a51675ea00a86a08a0abdd61d32f5c76720044ab513e863" },
                { "szl", "07df8ee4a461c73e42610cafec3c0bd21fc3f2ef9f33d1526e11d2012e952fd0de04259cd5d75ef55ebf93026d50e0139b38ca28938bcc16d766334e2bce5e20" },
                { "ta", "5b38448e4a1fa86c46190d94a4ad5e2bac249ec58a4e0a6519e4910fe87bdbd7165f03968bd3caadfb69298807d26db30123d4d90d2813b8af74e98a702a0da9" },
                { "te", "953b9ddb70d6af81d12f776de66601f6def19d1df0b82d8ff215bbab240e6c2364f32a5ed5664b6b61147e3360595a0ee62353a034981d6608a91c57ad938ebb" },
                { "tg", "21136517efd679c0974b7f48764400c8c88ea2c0ad5af7d9b84b839fda1866be61f378aff55e119841c5b9fa8b80d9a3a3305c5e2454841c619ea60642f1df12" },
                { "th", "74e44b927e5d1216931d6d72e8bc88926a260f23e0b49292cad615d83f681f9f7b5d9a9c9556a54d8653d54a6b2184523c1999fb32e78b0fda3479c6c48d74ed" },
                { "tl", "ae0c07f97b5e8d5176a1f056e32a94dc81f441c7f2c69609374e8490e34f9af3d792b7feb119ae9adb163cb24562cea7953f38c99021a50a86bbfbe2456e0c96" },
                { "tr", "06d3a697a3723d7d2da47618cb395a08ec53bf8abb14d1b55ec4c4e879b32ec680f6b69abcb7453d3a8fc3a4bddc39e0372bf69fc906f729a88b347c4872f40e" },
                { "trs", "0648500d8c79e746844ccf03334c35f02127aa1c5f2cb45eb8a6e77fb2f82afa24a3341f5952d708cfe33d4643663e345091223482efb4fb325a6901a3a3de72" },
                { "uk", "b7d728445234901dde3b073ac196608c5ac5ac8ad7dd795af0d09ca1e52d01b0372703afc8ec332ff7cb21d5000d3407ddaa30381e022e807eb4703e7d6bc4c1" },
                { "ur", "a488fc18422e8251dc9418fab7b92f0e5afc6a195d9f8819875196f67415c2ccd3e3d7d923fd6f32325515f32160ff66523e649cae676ca4b64744237677547e" },
                { "uz", "3123a497ebe75369fffa6f06c2f81157ce052eb4b92ce4f56ac6f300e6e182006cd2f7ef5bbdaeb7d391dc13fbab87d76099e0f8be0f42d44e8b3dbaed25d138" },
                { "vi", "42c8168a6d4be1ebb8b69a42ad4d5abfae40e02b1fdd5d85406f1df69923335f4ffe17de51b6077f396706097c1e55130eb818e29d56a50be65525f10c8c2a42" },
                { "xh", "11cd7fd10b4f2bc44f7f79983424c8ccc4a2f28404c83ffcc446c07ef25dd040573aedd790e67a7477faae0a3d0501680d944821731663a49dd73422b65aa822" },
                { "zh-CN", "95d5f4e2acd521e443134a391d08dc715181443b707218d6931dea8476305614cd844128ea752e83bc3605b829a4c545df105038dc5c1f2d5c67342a338edcbb" },
                { "zh-TW", "e6e9b758707419664d6e693b21cba262b5e389cb19138bca6495a247f422b0a5b0cb2a640878908ab20208c5e051948ff884be74a9e5ebe68c317541f8ffa161" }
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
