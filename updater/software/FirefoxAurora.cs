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
        private const string currentVersion = "143.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3b03adafd334fb36d6e7a9b4a99670f9938a1da4a5e76156bca7cc6e6b224078f04bbcda257eb5c1ddc874ab4ceca96f002a68cc95503ab8ff47c5c73e261d1f" },
                { "af", "c47b77d8b2414b791750517683fea3d46f5588fff3b8fb220e015ed2329f5557e96756d8d4ae7cd1f51e24488fcbe0ffff1ce865d111adc75e448377f1929d26" },
                { "an", "6082a0596aaa256393826544a2216f8e1c238d93e1080e5e9d1c10506eced69b7b6c33c1a8921f3b026a494baad2bb4f34ef2bcdc5c23b449d927f0ec89be26a" },
                { "ar", "def43992453163332ee93d9988c211c9f747e8341fed26feb0d76c2f68756b6e410a5669c16e1ed204e2732ba964dfde070deafa855fa80693e8fb513d93745d" },
                { "ast", "74c7dd067b7084ea818f8d2a117a35c4b856046c9d975eb5c4803633f9812e4e1f7bcfaa39c0b159401c3a9f73e4a92ac42a562196aa33c929b4e049aa2cb1d0" },
                { "az", "73f825485fb48275fe093095c7aa9d40c9de21539055f974b56cdea1aaccc9471247081d2ee349e04db022ed4f38cd6bd769d761bf5ad0f47f20f418d454d30d" },
                { "be", "6af6c28cf0531a19bd413800081f20f7221e66fa2ac399f5e5e92e5818b50c07f44e656a92a39e74efa6d12d41ff234cfde93e4a817b90686cf3ad4f11125981" },
                { "bg", "b0cea65ef6c7f0480ab998855db20220b8f6d4bbcdc655068aeba7d66feccade794140d5e059069a070213efd9e40dff2b5d93f5b9258d087bda21780d4c9986" },
                { "bn", "0ad3a2552b88aa81266a25516cf115578c19d4789f4f1a2d0a54b139885d00e78cbdd45648d0852f945c6e2270923b31f237845501a1a8ffb2386a1a003e5265" },
                { "br", "795371068f0e3f5b7e947d1f83c0bbe0987b95460c21252e328942e49b133e21ab01d9bfbce07a7ffec100c15a9c1810b29911e2349c4675c707fe0d1f16c63d" },
                { "bs", "065e001bb60e0631b06ac15ff8e70a4484d6e676c1d083834ac6cdfedba6eed94d1ed4534311128dc8c09a2205c5f564a055b337cbb86bc8de3c90d07f9970b1" },
                { "ca", "978a6e22e1bbc8613ec77717bcc497945e231ce882d105058ab559b2063bb6c31bb07fa2a7bf45301f8554c88a491690776fd4229a004f50f53a163c49a94f58" },
                { "cak", "1d7c317b961baf14271d1deb44ea1fe93ade687e8f375103c451188f47340c71cd1c2bfb287d48c107298c3b37fbda545e07a800887a47475f7b3f6f60d0b491" },
                { "cs", "43fd5741b88ce1751f3012e0151e5f26e5ea36e9908b342ca1edac477b5216d767d31bae907f01f3c0c09cc9e93717c7a7be27e7f0a283ab8417fb33e023d3cf" },
                { "cy", "10c8790789113782fa77ade42656b74206b8023db22dc4ad9fb1bcb3778942eb635419267497085387d91805ebba11950e0c7342059bb7924c3bd1c79cf159b4" },
                { "da", "16bc2000139f1ea12b10aaa04795083e546ab5a3f0560acb35391822bfcd8893288c79485e3dcb0e129a8c214be618eef30b6c0de449efd21957f8f8b87ed436" },
                { "de", "b2613f94ba6f92eca5afb098f3779c852fd47525f6e126148ad2363bdd1cdacf03d2a573944f027ea1c3f0ec53431bea17c7d140daa53dbb9616bf9ed8ed4d11" },
                { "dsb", "f4b9092a947961583a185ed1dce4f4075ed720ccf92fa18fe979f52651d84de22c48fc62528f6e9b82307e7815b416000ce0d7a14b3864d3935b0be2450bca01" },
                { "el", "26653fb91a053de5a4982c89c60a66c3c1fa71482dade4c7be180aa5d9d6c8c95340e96483977084c7d62bbded90874e9d3fd6c995d376c76bde677542927cb1" },
                { "en-CA", "0e1ee4fc6bc72af80dfb330ad8ef4c456fa812ad6454443ecd3b478fab4c5e24a48444a45755a0d345a6e18a387bd54133b86710b44ad20733fc411e8048bc7f" },
                { "en-GB", "8a298482030cbfac04f05c8e632e4ff2e56c6844d56a0cf514497fbafde7f29b63867b4d89b05dac3d622445d7926a02503676c7fb276585b6b745b38349cdc9" },
                { "en-US", "e703519fa07a1a92604d7050e982cdbcf2274ca48c772594c442a8ff05137d6577b8eb60fde8a4cd2ca451e5fba86a5fd9253cbdbd1550eb05ea08be030fb8dd" },
                { "eo", "60d824e4fa7f1d5f0d016f00efe219607fcb14d71396086c0e2ca24117a6a0b6a6c51f4a5444154238f6ff238ad40547d7c4c2df996735c478862a52c0fb3d33" },
                { "es-AR", "49b1421c305f773f653cb6b597b64a621c19eedb49016e238208b1ad44fb1ff90e67c59f7c1260926915eeaa220466c0bbc62f66b9ae58e01577e3c799fdcb35" },
                { "es-CL", "fc49170b2fbeeb9dc808b03da6d979e2626ea5c2a94c880a3f5d50cbb56c7978f8e244d22ae5b37c041cb37726b1ed5ed1061d1cafe60f85c979aa394fda3297" },
                { "es-ES", "0fc6f097f1666428dc4464dca861219381a7530560af8fb62e61c7b98c87e8abb2b3944bd6d44add460457dec29c145711e5435a39be481482b2713eac5e2fc6" },
                { "es-MX", "41c780745256f17fc700e48c9348a959f11bc388cda3e74eb2ffd403a162f81365e0789f6125a83917c4b8421d514649db8be729f85b0794956f93b01cc6f5d0" },
                { "et", "cfd5ea76fb8afead19d425067845f127c3ed7c383bb26390d8383ef68c966f342f103fa73be0f88af1b87c8ee8d405f8b6b56bd025b0b413af1b98e9969f6545" },
                { "eu", "bd23d63a2f63b09d79c36aca6fdd0b421190d2139758ccf37ebea66690909534fa86d38f10a51ba3fbed54f3f55c3d834b13ffee540dc31eec9ea9e17708b6f8" },
                { "fa", "876d01e195547ea961c21c3362cbc4f2f1dd0f3f1c99f969ba9e6d20e2cc27bdc1cb9aed644d642636b85acf9e509cf7d7cd4a733a58bb9ef92488e5ece7027b" },
                { "ff", "8663943cab085e28a755a7c79415bcfc75a386ea429facd8b2ac79a9cb3d68dbe7a19a7fec39ac1f64e480c763a27568131553a9629613a59314783baab01e8c" },
                { "fi", "455122336a37dd4a58e4b62934815588e11e7c1279a40033ccb913ffef70f5a165c9420d942d5cb3b7c8d62f1fc32582a061937de8650de945549665d0e45ccc" },
                { "fr", "4eaeb955fcbf4278b157208ef3d1efa7eb26acafe1b212f6b0089a159d3724f8e79dabd420c7cabc38bfc0543d6b061ad78fe7d669eed222ffe4783f7a7c9ec4" },
                { "fur", "ce8cb479790fdebceebc8cff2fe4d6fd915a858adca9794c02cb079b88a5b35b96aa699ee850f4c5fda49612ff0b961801515cfbcfadc3fc6a3b150afb320aa9" },
                { "fy-NL", "17a1196f6a48fb6676aceace92260673abafa671837737841d1a0005724af3d6bf86f10d4eac03d32f3fe752d6060c1bc0ab429198a09819f04570759db87554" },
                { "ga-IE", "e1a6d2b5e6166bf82653ae93e79b4549afe417586ccd716351948c70197d314d9f448b8881a71955fd38caeb79cd530c236bf6750387640e7306084b33bdd3ab" },
                { "gd", "b2a79cfb962cc458c17a73d48b012504567696dd43e8b74cedbdb47392a14f2e1043f2a8981145ef5308b8caa8ac57f808c31e04ead9de1b56e5e458bd512646" },
                { "gl", "62eeb55e3a3c0fae4dc27526f8ae5ae9a0e3fb1c9c1c910bd567162f88779f01fa8141847e220c87846dc0d2e389a0e0d013a34509dbb5d8d837fcdfc25a327e" },
                { "gn", "ca99110a0ac848865f9c01f01a613d4b839dfe441b9646a78d662578ad94588dcf8f6f2cb6b95ba47ace9455333bc0b5ef54cfd521b92af69f28c09dc9bba3ca" },
                { "gu-IN", "fdba392ce57ebba2327646fb79f0a0314a7684122b41c6b22d9c902967544aa7ecb1cfe4d7831df3eb00cf96a347b3133c79b1363a3e68a4f5e6d9b04c6af40d" },
                { "he", "517499a086b6496fb888307337d61b20e15345941d3490182bc45d2b53e30cf8982af5b14b1b3c1b3c80c2f3d1b8f40c0762c33657c619d20dc1b78db84a854b" },
                { "hi-IN", "7e2e6d13a3e665eed641c385c3bd48d30d15935ff38b09ffeb9714ac26cc88cda684ba0b96eccfb61f8723a40329d2c742a0dd0931b53cc1a74c618c88a85411" },
                { "hr", "15d4662efc6c11e18550dcfa0def4b8555bd4828c8e870b6acb04695abf2f41e29030e832ffc1dece3dd54b15abbe51b70897119d502b3520bdaa195ff6f0ac4" },
                { "hsb", "2badddef7560ed0288674e4a2dc70241f5614dc5f47308ddf289e4b8cf1349f4265e6150b5f70375700c94a2d7c4308414d36b673e30fedbefd766590c6342ef" },
                { "hu", "b3d7016f9a7e6a0f938ab88f1fddb49e1437f75980f060f6768e9e41dc5698b59139f6628a286f220510560685d6c6d49f93ec774dd4d6c020aed02f598485ec" },
                { "hy-AM", "834aefaa0f332496f2bfbbe37048cff62fb90697371c3127abebac7c448fc819a2eaf13f5f963bdabf3c3bbdcdf92f8d6b5393891f5bbd07d59c27d18cec426e" },
                { "ia", "748b0e4b3ffba7e2dfa3e52f2ed43fd301fc4bb1337855f0e09ffc7e91ca757227cb57bbe731483f22bf96a5711bfeaeb47a8c4ca90e781d5f8f758e89a7405d" },
                { "id", "e746fa5bcb9a9df3f20bd08a6d7771481cfd0e2479c0924f7ecef06482472f8e59e98c5e9377d62688d8e6b946ff45ebeb53f5b29b3194b7754c15eca7210d6e" },
                { "is", "2262a0be1dbf24c382f45de1a75e5955df8146e4ca702352fab90b06f6fbff1d64fa4face69a7b457b073e43215ff6769ac02eaa6c94c605ab3bfa5e8f876aa2" },
                { "it", "f626154e8a9a42fdb8b59bc485bb0cd1f45357ab13acc37862f5e4bf64ae8198087c0e05c39f83d8fd75f3e7a51a14008a737c9cb168a071635bb0dab7a15c3e" },
                { "ja", "4b0be5ce7471fb9857caa7cd18a1f73d4014a01a72e2eafc863c072e83332a6076aea04fe31348612a6452e8feb7b5ac78cbc46e9ec0f436f3fdc7123b40d533" },
                { "ka", "fc9343d00511197f23d3568ec66353c5bc79336d99785d8a822b8b1375aa1896c6bf3314c87bd4ee1467e5b2d8578b09f83cf92bc2c11addf18f8f1fc0d49b0c" },
                { "kab", "d534fb255a7ec7b49fd98ea251779f526733985deb4e5b367008ad0735fba08961ef049a2ebc9da0c2dc89a3ea295b68a0bf9977d21b07f4f6b6a03f5625b343" },
                { "kk", "4571ae492cf377168ab8ec05bb8849d379187a1f683abdc58196ae1f312ec5f1949c6c7701fce317ca48c883e85619ba608b59d8b18a16dcc35c71b55c98b351" },
                { "km", "d08c0406acef3c80987171cd84a68cc79662ae0e7f9faad5b9a53ba56876737f59e0afd611f81e3d24bd5116b3b4a4deba61bca0188bd46aca08942d0fbfc102" },
                { "kn", "2d7f981e2a4a4c799daf14604d958df0cd830c1c42e55fabf8155bc43f931686d0018c80d58c255a1da324aab81f8f723d3d218203e35776bcff4c60a11a3e4d" },
                { "ko", "c812bc2816b621b62b6350c0d468185881dfc1e059cf0782838552d9a26dab3b7a8169bd5f1c459a26c33dc882ec394cd1cd1a4629662617cc17260413369c6c" },
                { "lij", "18ab62f161caca1aa83da5bcffe5f34661e55cd429256890c995f307e230601b9a4a1d2f8e50f8606827f789afc688ee6fa3d2392bca29d16f3022228eaf63c3" },
                { "lt", "72142d46660c12407b65312f9a2b9944df24ce3dc46c9ad158d076906e70678e32d5e8b1e6dbb46b07c575e030d634e4f46cd15be3cc1dec6548ad78f934976a" },
                { "lv", "7a12b3abd4cf3c7c13989f4aeb6cabd831792e811943a020eca471aeb71c42840e93fda81bdf940b28be6f4b83dacdf7557ad99a693012c7330ed582fad02245" },
                { "mk", "26d3b622c21f6f9f39aa48df225c85b516073362a5ea26acdd0a33206490597afe9ade72f91d1a4f20e7742460a1ffe239369f2bfbe941b7648204ae0030acf2" },
                { "mr", "71bf19cdd63b4fd864639819e769c8a592c96ef48f8cbb12c569268e2123347f9e6398f2c53105a7335f2686bfb35b3075f7a13d35f224d1b1ff3aba5b7cc38b" },
                { "ms", "288365b530926b57d4266da705f28a88aae4b1d1a0a18eb208d06ffd6961b45b4e6059eb5a468616fe24bf73a5b1cd4595d5b5d732125d3458c9d90a6afc2a25" },
                { "my", "b6e5469ea2c3f59341c9e7352377ad569b73ab683c63d6680ba85e995cc23a06fff02e91e7f5fb3f81715cb3f1b3f2c0beb05e0fffee7c5960bd1d325fb96ebe" },
                { "nb-NO", "ff3ef26f3e6cadbc14460cd60e5bc405e449eaed5afa310934f0af2cf0410a7a1a36013d38ea7e500a686daa3111076097116045b62a5e5befd223390a27647d" },
                { "ne-NP", "3ce93725f3cd6dda7a591c5255ea404aa55ecace621eb2d74e498a0482d2e0fa58559ea0ef0fee610450e1e0f6033c1b98b937ee833fbc98f75e9e08203b3816" },
                { "nl", "bec832f8bfae551186a92c7b51aed6191e3417c0b9295067f3d4730a254e2942fa61c5afc447369b092eaa7407b8be40ccf4cd677414b73f76969fc54f512403" },
                { "nn-NO", "4c16b8695b98be845ce504b99850a141d516452f7c09219acb144198a210f0798b64731a8ae8004a07a8855938b49c49c4a054aaad48db42e25e3561f6313f36" },
                { "oc", "86e7aea832299dc144983fcbd95b6f3aa35efa894bcfb6c2c069ecd35a8b3ffd94a515e21e27e0ce06ac48e688be4a8bc641c8465a11f91522de72b9843f4f90" },
                { "pa-IN", "eb6a3fdf20b7ccc6ad7887a8d18304be627bdcd1541b3f910fc4c2a7aec8261a157e623422522465a7b886c0bcefcf3ee4900415891c15e956824db30119510b" },
                { "pl", "3aec8ec77ab157b9f97ce9a1c48d50948c96a55efc9bbb3ec8596fdd3e9ad431a2f6e49ba92af06fa8acd5d31e6d6e411891b4f0962f25ec02e6f19bca3dc1e8" },
                { "pt-BR", "416cd4a67eb56d99fb265bda514ec50ba4b44cf71ef78e35e9dd6ef5e4c3de1d6bab5e659e1760c9e716d2d17bb45c31e99caf1618f65a9a8257220ab41e5f3f" },
                { "pt-PT", "6e6b532910f9b13c7f6cf728d0e935800b50d1dd7d2883e97ff640d04b382541c17f8c93a035150f5ccdf6cd9c4fb6126f67606a3a4c9849cc80b9f21234ab51" },
                { "rm", "ca353f49ef1f31c201ed94efa2750424f7f851cc568b66b82978dc2066046aa0e4ad2e1956fa433efb4a83db682c2ac54849612e91fe1b2ce445f0c46157cc15" },
                { "ro", "9761b40e878910fe328aff265b043f6b28cdc19d5359ebc737798fea56c79f46d7f66bae8d46b356ce36372d84bbf14bb63728077051ffc8c7eefed934ba75f4" },
                { "ru", "cf34ab5ef4497b74c4e69566e8cd6cfa8e68681babeb2fbfaf775870a8ccd2d1ac7a45979babd0ecbd11df2f0bbb4abfa3522ec43746267f8bc266c5b682525d" },
                { "sat", "ad8054c33cb516dd2c70c95e96c38415eb295b27e1c61280cbaab8772407795196672041d751b3c3e6d7cbdb94169c0376594ed4b653527225a70496bb828aea" },
                { "sc", "fdb652c2f036c2a9d5eb280f270a907b959dd9bac15bfa33caea72c30dbd817a2d0ebc26663517bb2a57fc699a58df06ce79240735a006be422c530c79250205" },
                { "sco", "fb518df5d8970d58bae5f551de9d39cebf94294358d2fcda6dff39c9ee39b32bbf01345f987a80ee1399771504d1065186f4e7841a2f746303ec240b00ad98fe" },
                { "si", "952b79e4210f0770ce18c98d404d53e9a7b3c66c9642479d896027509cfd00ce2d28a4d0d1c374a29f0936d824733bc3a79714ea5d16a5fea71cbf3b588c7efe" },
                { "sk", "cd7fcad10c6b35371847c3bd5efbed0b4c9e26bc0d7d5eb8fc5e3e559786556df57f3bd61a89600480fe303d3dd49a34778d32354b36cc7f5e4fe476e9d4aa0b" },
                { "skr", "f71a878a387daa9486569ef62e67f623bd55dc5bcfb24703d7f2ef9c488a537a5f6cd0219798c6b829865689d55df2d15450b5c3c8879e8022a9220120ecf9bc" },
                { "sl", "0f1dd4cfaece666ac5cc74472bca6345b44702ecf61bc67d4325ccf8507c7339c8c985d92ea2d8074257a633986c6b36e8bf3ade06a26fa6e324d86c2ce67c35" },
                { "son", "df3e5801a9e5832fb91aa111b6ef1078532970ae02ab6781381dcc49bbee454cd4d2e925a2ad3edd9126c64a0c21cab4ef127457e8337b841af973f82306dcee" },
                { "sq", "94c7e475aa2285fdff21943af3adf09bdc87d0454c7c2a7c5efbea0fdcda470c83fd40b43c30dd56990c464b98ff31b277c7fa6873f09d832ebee29570bec880" },
                { "sr", "6bd796d5c42708a60c889b72a670cb22d99b055598ecdcbd6241924f0bc282f1f5fb53cc8e305b480aef3799314d8de94150ab12c82deb17f07969650f92d09c" },
                { "sv-SE", "57f9d99de8c351e0046ff3867d65e849944880bc46c63d7a836d808314baa60e655383d03d73449d745233eb1b9d29acf735052f90b9283d385edbeebe81c858" },
                { "szl", "fefff15d59844525d494314f223aaf09068a4b0d8b0c97f13a0f2b31c9d5b3d3ec18a1451102701d8f835b7176bcaa5918ee330321c1614d8a9e2eab5a7db5d2" },
                { "ta", "5261302709c4008c5b5f6d766f9526a72eeb3e117b07440b075998e934dcfc0a840f94b2b028a848b321ab2c2b46db3e4690229f1e5a1b02c7d1341341a2cbaf" },
                { "te", "cfebcd690b6686dd66c2acdfc853e8044fdb460c8d5db0cbc52ca4bd97b4d885bdb745dc2a3c153fc14c652c48de0aee9a00e5291129949d467cca72d76e7661" },
                { "tg", "113785ca3643acae516b4ef99cda09f30fa0358e1c6abcd6ec19c195030c6458b33aea53366e31b2f780f89f299a31efb9576f1cf36949ab2306e36a6f9d102a" },
                { "th", "492382dbf3a662a5981e4d11b1b98b9a476702939fa434500d9fc92346f029eada407c0fb83f3c6e4bbc04f55c792bf78bba6a74916ad6cfed0b4d73aacc87bc" },
                { "tl", "4f1fb5718f4d1d05bb34876d2dea2c7b0083eba99e16c5d3c58bb1a67abeadfad9cb10e33c9d3059b973e4ee6645afa6da3b826299c68b5e36f2fd7ed9e94fdb" },
                { "tr", "533ce854b1b0b77e1ca63a68259f6e89cfaf78b62e9783bcab15cd5fb77eb985a0e849dad3ff17fa3f532d099fe5e57e10c185b1ca8cf644083307e5a8cb40ea" },
                { "trs", "29f0ccc908d1cf87759c67cb01e6dae8ccef9948f8038a882eea6c53060e49b39b8a7ab2bb53c9a4d033d098d90dea1e612719e4c2a39f951e50317390720af4" },
                { "uk", "a7dde7ba6fdb124c3a2b88f2df2d70be4b5b2f7a43ab43ac836485fff250c113c766337c8cd4470b5cb10c2166ba819461c08e64c79cc0908ef29c6452aed4a9" },
                { "ur", "8647907aa7ee25e8edf290fd380567673e8eb406b6d891c071e115395c24ad35f7fce119aae5dd72ae4d3d3f0143da77b7be631ca050b1997e130847b0e7fc6b" },
                { "uz", "315569d4cf5a4bba743c0b032149a541b8557952a5295f9b5dedb80f4aef18eb4b3aaca90961b25b419ad5fb086ed40c7a9d6f92425a4ce7c2edbc2cfb781cab" },
                { "vi", "9fd033abd6caf593ed5d4f5ce132c70b80f7becbf38eeb29026115e4b635cd734c9355030b69f9770b5348068cc6a56fc350d332894364deece7cde5415f4295" },
                { "xh", "cf121ebb68b529f5b6fcc86f58239053e5537a632e58172d83908738e67c71aaa7c9a7d2152aa56a4276d6b41898536f54e7be97c564be5f6c60e5970a466d87" },
                { "zh-CN", "e77c7de78d7b720a20f30d5a1679300d87f7319dfbd45e7c61cc615df1cd4c17f0809081cddc14db8ba63841102cabff7469b2abdd5947baba747f0de972a718" },
                { "zh-TW", "187a914e0ccb266c8bfd60b90a71269e6b0d5e1d6db3b4d3e3f6109bc993e5f317a345d604f666407ec0a07d656d301ed6c7c0e7cc0bb19875228207a51559de" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "412f8bc3455d9dc9a35e178555eac0b7e5751d68f4b80eb65be6e1b0456eb78c877d493d4113d616019afce31eee7bcfc07439b068c5c313ddc59683c47f6492" },
                { "af", "6cde6b2976fcd3afb59c5168cabe640635e20242c4a97e9c9034177ab6d299fd14c041aa38c220a3e9fcdfa4da6ca36b76a58c368af82dfc4e991bd15baa4338" },
                { "an", "32ecc3f1bb1f8e86dfb8e95a58423de7ed478b921968f6c9e5e744f64073ba8082ed5c7683457b2c7e0463ba39327803fafd9b6b15ee8bb09dcd8b84bdaf2e31" },
                { "ar", "f4dec51806ce0c537458e4750d5aadf53d7d825a36c90cded3120c75d507a0f7baf07430332543c34c366bc6d2091363da81fd97ffe64642a857c19d7235e288" },
                { "ast", "ad2502f55c9fbfec11611f102cdef94f075f6907f70843a4cb69c4e7f43c8d34dff1ce0a7df64d6927eb49b7b344a8ae16e3fc5df46bf51a5f8424c4388a6cda" },
                { "az", "ebaa146748268e5b2ba40a2167bc677d1161021d07caa5975b08d1525bb74eb876940b5e88f7e026b99d53fb6018f11fa2d1ef8a656d959373002cf8f18207f6" },
                { "be", "3b2129fadf1cced5378d8c9f91eb6b6fe0d6931e0c05422d0eb07bff3f809dfcb3e5c14fa23b9736daf57d6e0057161630d7bc55e0261bfe533b6e0b44c67062" },
                { "bg", "af5a317c6bcc66688b6145b3c79d19e96306a47ec1a68b61ebd2d396bd099e64bf4ddeae1dd7241fd2099f03569b0555d7df9b196f063058ffb9c8f892e4a878" },
                { "bn", "e60bee60f2c50ed2be902d7817bfa2a640510e15a86a0f6049c86648f8fa8b249df184cdf72c9291616d0f50be923f3dab2a755786040cb293af32b295c64bc6" },
                { "br", "294fa97b6dbffe21f7fbc983bfc85d3e222bda28b6aab794819d4f92df137d8ce4b8a57dde571fb5a2d68dfa5e07b95935626f467bb6b7394dca395edb67c6a9" },
                { "bs", "209230e00ffbe9c49cde3a18028e07a427f93a5d714d4d270752b26999e772160dc7b2f855281744a65df01e414023db259e250e071071a2fcfdc7df844e659b" },
                { "ca", "ba71bb144b5479e16d9e0b730e266070ae95bde969c6d3b3ced1896d50a34a6d361b711f577d962fbeef86845f5a0670e1ef537dd41662cd7e180ebeba776b24" },
                { "cak", "cc96cebeb849ec2aca111aff247d099d3046fd2662c520623239091d745ceebc074f94365be65c2c9be84f09dbe81bb080f8db996fade49e999487e15536a13b" },
                { "cs", "bf05a79642ee595cb50201cbee19cc1839339e654333bc9112848c2792cbfe4fe44eef123c7f30b97263f11d58946cac3c74bc819bf673d29ff9e35e4c0a8f89" },
                { "cy", "09a9f841d2f70807a33fff3c9ce81d7b24e27f70b1c0cfe5abc3c66e2ced16c8c71c4c435a087b66559a17a57412469272ba648d4c42dce569303e5be9929395" },
                { "da", "9b19e32052557602bdd5c49342172195d068bc25e3c73ae1a570a13c37414ae504a988bd6f58a3c85327ff57806783d1ca2ca1368f8a955fd34c9e8d72df794b" },
                { "de", "2ca47b011fdcf6ed287505083eff795e1f60a3c653cc06f1aecc7fcde948d77435e8cd52aa990078f47ad8803b1bb3b4bce5f6f8a1cc6bb14fce916b79191d8f" },
                { "dsb", "c07926e9361ef662a7697cc6b64062fba3356c98c115ead39714fb858de022112c545f9cd00ffd30e9814a24adc89188e7e9861bd627e69b414b4a655bc4ac48" },
                { "el", "8cdecf019b6cb47448258417646fab6964fa41b2f25ecc531e48be6845b29808ed19d07cd00b98bb35b26822acdf342eac0ed7dd15d3b55ef3baf9a7359c3f9f" },
                { "en-CA", "e6145b303d93da1eb477ed3fdcf3283af357509dd8b001286bb39b3e9768c707181f9f59270f1297c73c19420e381ca727d70d458944cb43bd009f93c44711f6" },
                { "en-GB", "f7be08d22ad770194a8ac71fac1fae64426842866d4b76459603d74aacd479906ae9d07601099927c691af98b466f9c5cda66252fa9ec2cc0ee61b51e59e0626" },
                { "en-US", "26f1c48357c3552c6dc20395ef7b210dbcbbda3d237c2f6f926ba13fd2f9be2fd58ad717f19f78f4571805c1122f2eec000f4a03d980404a85d89e1349abdf3e" },
                { "eo", "022e1bc474dddc62e71e0b1bf99d7d3f5fc4cce0dc64d7ded54ebf46a8c2011462cb33983ebbf21f9495a9807c8676c3c6f7d9b041bb1269618c70eee682580d" },
                { "es-AR", "c4de2600b554b60cf55a969388e639f83676b989f31e40c5f4663c4b8429288c001ee9cb4c7c51312c0ac0815d5e1e64958568cdefb9c8b2c7c49ab3d4d8cf41" },
                { "es-CL", "01733bcf567e793c7dc77e63b1d0e44e6a3f9c5f160e98c87a359bd4a1ebccb47b669dfe8c6d027a316a63dcfe7a721a28e0c84c41101aee1ea24cb88c5e22a3" },
                { "es-ES", "2123fc08b1cba34cb6dd205eec36adc5ad5e2f33ac5f89b6ba83b58fb5d8db688ceef3c9a48ef925cae7335862169e2adb947f23afccb5566a7fa97263b4dde8" },
                { "es-MX", "874776723897db41ed16208c2c35aa11af9bcdd69789ea7fd1820b92aab6810869961cfee012031056b002722e02365b558b399ca6c37fbc3ef70375f8b08011" },
                { "et", "d37e7851d64cb45e053af238f2dc1ef17db33de6e45f61523b930f3e3e95af87a02105986cbcd0a3d3d1498d1b88969356b2f32cd3f0eaffe2331dcde4c1868e" },
                { "eu", "2c08675c1d018c0845db41729f07a88c22a5b08a76d97330faa1bfd0f65c58da749819c5f97d49dd7d6e89f679e9dfeea99e44a4e844133bc4cfb54bef6d6434" },
                { "fa", "08700cf80959ac861f006ed185978b51b809211661108e8ec17c252e8e00cee58ed3242ac99f54c4094961d01bc355fed05e3fd94f91981d5747fed3a713bbfa" },
                { "ff", "37b5bae8412e4daff253c6cc53bc768d1f90a73fac00d143c179632e619ad1d53d9acf0b2ec24618047b57efa9a4f2d16ebcd5382f4f6a45a7a9bb33ace6b22d" },
                { "fi", "a13978da164e429563ef558087fc81f6432dd2c7754bc9ed37225c820cdea86b631a9afd6e3665227ce6286e172182daa64c236c6c97fc0a4b8afc230c83c1e5" },
                { "fr", "69cbfef8659d988612617b8fcbc746f47ee2db947fc3452097aecb8396a1b02264617f0476f914b3eb184f967007b3961494b48f63b07416a8c63724e237c2d9" },
                { "fur", "689f493f46271c8e7f2425b4c8707fb56fee40453e92da248c92333206c9fdae94d0d26e194167a9cf1b2e3212cc69abd45486e609dd81e87f6960412a8f6c29" },
                { "fy-NL", "304a73b2251412031c67ecb44613f3aa680b3beb9ae3db6802ca9e3044874c20bd355a3910afb32fb72f8a5d815e31430ae97365348e55bbd2858d31604268dd" },
                { "ga-IE", "2f55d373e7324666a1c5f9751c0c039dedee75a16c373f9ef70cc39a602a76b907a48ea04149c0b74609c72814175c83e47f662cc2711bc5efe7d29d0ee65f05" },
                { "gd", "6a2b0464764a9b049867ba4787f90a5927db229c254aa33ba72f950337ff3646ba4038b3423c1ce1dca9dbe16586e8b436e4e347d4de41080ad97f8d6798ad3e" },
                { "gl", "81a16b55a0c1a2badb1b8444857d17fd61ea41f4cde7a75dd8f381c5b72314bc9855938535368db4c92caa19b1e9a42c220458958f4518788ecc0c73babc9dcf" },
                { "gn", "0474e09484619042a93d9e8325e3927a0270aee66f40e4c4894e28fd75cde75586420fcdb4d2d2926965d2692c5db0a6a1d97efdba3ca29b7a93b22187a0aedf" },
                { "gu-IN", "47431defa1fc211546a3c6c1b4cfda0832c90fd2780d657401465b85befc3a722b58005d44a499fc62ce486531f86e891c3847586d0aa018695a26f74c94ff88" },
                { "he", "8bec1783ac93cad30cabba9c9b94936de52442da149d35a6df1c48a58656c9179e7d15ad9cee582990db03dc44ace47f6f0584dd5dc4e124ba9859c56e395863" },
                { "hi-IN", "0a53d348e51e2cec8476c3994a9860042e6347211202aa0d90e389c867a32a290abead4437b44a5df4607fe76c2a1fc696acda08027285221056d9a0e481c9fa" },
                { "hr", "50791a8d0ca95e7bc8ba4f53839c1532e60cebbcf9f473bc4098121ea9d4b38c848568d3e5b587c61f9668440745e1725bfbfd1a527f3621a47d77773371c8e5" },
                { "hsb", "32cc466f2c16814c828a7e9d92ff60b87df752c1c3d906fc19ee95c16d2d0f99a77ee18e9bdb668056b7258005288fad83dd5e4fbe24691151b38aa24e69bbde" },
                { "hu", "d7796a69c7e89622cfce4e5897371bcaae0de92dcde9d7cd06cf413594e5ee5e0d395434a37d51301217c8aa59ad61541230eba323e43cc7f62e783f4cf426d3" },
                { "hy-AM", "c20c8fd9e1e7e11f219e7f2851b26ff15e9f282b1886ab802c37119a570b3793152fcd55116049ad9f5a970d51f256808b020a4b4401bce2be59787db1e6bac9" },
                { "ia", "d8f3f9bda8a5000cfadc9a51b5d1675a10e10530660b8b7a0bd6aa28117da55d2a986a564d984a0e1bcd9364fb5061dc6e9d7ed51bb29547ef2d58e67e8d3385" },
                { "id", "65aa857ead69631f9c608446d8154ccedea1d848de64e32fb51a69f7b976a31edf705bab67fe2a5860ae6f1f2ad74305457479de698cb1f0e787da93f1f1466a" },
                { "is", "e42315a5759730f885a77a788525e3cac54e3a7b3c44fb1c2cd3fd53b9e295d91e6a9662c450c443e015d401ab6dbb78b6608a9e603410405bfb3949afe67cd5" },
                { "it", "04ac89792e3d2ce06fea063672d993092c3e14cd5832a784b4c5aad5d1e7f9140d166432dd44f7ccfbdcf37c3428cee6a57673642d0e45243e98c78489d87af0" },
                { "ja", "1f6a2328ae63926d471ceccb164cb99f2cc64c770fbc794dfa9c4121c2640ed9c0e9b1892291e5a2bed070499e3b490814721c3dd7775b8a8fe0812d9caa792a" },
                { "ka", "91210491ff55c1efcda706fc3a425f75c06d02ac83b1a56d640053d2ef67ea4581cae565a8e524e44aa27e0ba69947746c9e2f8910f9dc4f62d5a62245b55f79" },
                { "kab", "cc89854252799deb1a1963e5344adcc8517a7f4602c57c0a7ab386e5fb49f9fb14550bf433595eb39c5ce38ded0cf432a6dcaa328a0e554ae59820aa03fcaf03" },
                { "kk", "c025f160b55ed98c50d3c313d6370558ce7e4a9ddd7082436d227333adc6c97bdfded2b3574adaf1261b44cb1700bd764b29d61051007742316ec0f8bcad7c1e" },
                { "km", "10627790c811a827d023a82c7c8df81550b2d9991fd25716064d280e924115619bb16ebe7e19d71f4afc2b7b3fb1cf669c8d74d83ece09802caa34386f72957b" },
                { "kn", "58f209f630a0d78772ecb388499ec320cf10f7f52da8822f666bb1d4a808995f402dc7ba9eaa541ebac8f5b75a1d9fdf70f35342ccaf2671cad35ebd8ee0c15d" },
                { "ko", "8a9abf42653985026958d8f9bda3e243773c8afd7d733442d18491a6812ddca55b4c39d24203778b4d8a5f65f27a10ab7663a0ea467da4d4abffa770de4ec9fe" },
                { "lij", "e24a3a86b2e9bc53cf0e084926c40fff897715768eea459a9f4ef968c8986af4fb5ee0d4cbfe83a8e2f4f7803c4dfca3de08c42e6a9620f7dbb5c79024c1e1eb" },
                { "lt", "f8218ab44d528892bd5cfb98d193e047bcd1f84c030ac1aa17dfda3602d10d5b745620fa89c247309de52fd31de72bdca3458e177666ff11c856ea041b44ad96" },
                { "lv", "833f8feb56c289b4f992038b3593d8a07b257064660e69b42dce7aa1222eeb19ddc1aecadd07a57920a4b1ddf9b647035528de8ca5baf380a78b270aa4b2ece9" },
                { "mk", "85d81781887fc1f65073abb112e2b23ccb50f41970a7dfbb65b3d6e89cccb3f16c4f0593a061af2d4812fe3fce687a8a1f8e4b92599bbc8546434144ed46d126" },
                { "mr", "2ca97bf3bf7e813d753a2a638c01990de17b92048ec15cd642ae818665af40dfd01acca393e79837c609473500b6fada14920a223415ac4134506659ed1e6459" },
                { "ms", "93a69c9e54f119c262ccc275353362740545964d13a0859aba25ef513a4b399b97f00c0fa95ac6834188a52ef12d684e63a9a24adf35492d05d2d8d12f19edd5" },
                { "my", "e0ef3f9f8d44328bb5b2cbb89906998db665d2e446635144960c42bca06289ffe97c92df215ec0fa2b220d97411bb0009a291a09af45fd96a3c3975536ef2312" },
                { "nb-NO", "daca273894e873bcef0e5cdd3900cd9061fb9de3302bdb42608647ac976ca7a30f2524060ca5b2a8300b4bf5ef90f7d8f9eb53df9f0af1ca45a4b2dde702800a" },
                { "ne-NP", "05e4432a14cccfeda1274af5dfdd2d7b9771d699da24eba3e4a0856d77c8bbcf67f383573393a463fee85158d140b30e2a8fdf8d60a87373aca0745af23c70e7" },
                { "nl", "a22a1308672c1a32c1727449a49e088f3db741f1372ed2eaad640b4b59e7f80ab70c23fa7d51d7dd8da463cadee3ef1c69427f01f5eaa95f2719c0bc1e39e0fd" },
                { "nn-NO", "fc50a03836a4bf7182f8e4541029a2e06f1fc0ce98e3d0a46741dea55541d904015e90c59a0b61e278d775a8e0153f5d2364631d7b96bf16f942dc135ab5d977" },
                { "oc", "db6253f4f215ca830c8d50bee98ae67127febf29c64bbc90dcd02f035a3c702e78cebc7c847c44425fba706558a633dc57781ac66f82c06698c75d2a67998fab" },
                { "pa-IN", "061176ab35ce0de6c52bdd1767b0b1402778979c52524b79c0f05f778d45c4d6b09e91addc6d64f31e5165d1a18cb3cd9a52b539f307ba90c05e48efc3749abf" },
                { "pl", "27c2e052b97490292429f5950f5e679b08e6f07ba2a980bc441f8a12c075d983be9053186477ec9d141e8d7f979b2a7589172fdfc3cdf584fc98c4047399a205" },
                { "pt-BR", "cc3578c630b61b85863534c02109a4aadaedfc0ebbad9c385378f1e55d8d935a9c840e628b6f63d9189194865880374f34466003194b136d58bdc7333a1603db" },
                { "pt-PT", "1f6f80f505902104d0f1db9773de26b043ddae3407cb9b628fbafe5ff9b8f7c07c5130febd2f005026bcad558e2cd465127efadd35df4778ae062aadb405fb82" },
                { "rm", "6fdf5eab104b358aa34d5d44fc503808f2599215072a9b85f13478f9ca2366932757886f98f95c25e409c294137f3f74508ccda4ca330530ad8bd120521b9ec6" },
                { "ro", "a89849ef7eb2c321fbd6cd05f69b5f2866ff9835dc62cf69d81ecdaa15ca3a89bb6d210419dffba305d8dc75545a53d465ff17b3de6ad35d727c64e483e03510" },
                { "ru", "cf34abf58347dac0f0383caff78fb7e726deb655d6ac4cfdf163f8da74c4abc9586695819364a37101c43d11b11b9960c3c1c63e8f7ae9e5c3f3e7fc5107ae38" },
                { "sat", "d51bd9307005e5553e9a750bdbb3ba35098350ef5f9ea11a376cf5f58b40a69d4d314a2a7478b02734d7e1de29e9274c7d0c044b2f1dd120c82baadedf6a599b" },
                { "sc", "47f345b1838c712cfb8adfae810f1e251ac6aaeb1b4c2ea6408c14a427af37079b35699957200846b5f62295274689ad9985f43f3d8e148226809fcc82dbe527" },
                { "sco", "3a9e4a4b52d8b930d1381852d4b817be55760af9a10a4b5e0c0131a40fbe714e0383077eceb9a1a0a41f4f903a303c907cc9fee4b74eebb144a901fe7fba05a4" },
                { "si", "a7651e10c5950284caa081645beb994222b3f4d203cb667d951dcaee50461f69cc56019ac5a73b0b11e846bc21fb514c0bac9f476d2ffa217329476e7b013884" },
                { "sk", "71d2b8c93ee40bb230b6e3adaaca788afe398e8ba63dede2451c68c3b0bf0a991ce163e48032f7944cfebbf4c0e5962790c0d7cd4faf51a8cb9904fe6121b9c3" },
                { "skr", "192587e623d7938bf267319c664bfd4326e9e2f86ea6eec7cad119404100144dadcdedaefae9425f8b5634123f1bcce35d2a235beed78dca258179f588bf9fba" },
                { "sl", "3e4675cd58f0b55c7f31dd03c14e3db95de020bbb8d753ecc41961b5c7da3ad84beb70f09fc3de2ac5f96418c68ce49bbb3006e9a06a3d92f85d70419fa14c62" },
                { "son", "2a37472820b9344092113fb7ce5e0082ea90b9ced8ee57c7caf72397ddd08c707fada53c8f62f00a75ce70c117a1872fccd048456646b69433f4bdf424be2e7e" },
                { "sq", "ec141614d91b078563d3192571093ba0a9b5e48dbba8e858a01601a977ec87a656025ea160c05b30fa571907628838a87d799c0c74e8fad1cfaf789d086e7070" },
                { "sr", "716b54c4a00179c8697c197b0b76838512e1ca1ce127719813c3b9b929bc743364e7ecce6a322aefb72e2304023bd257ea144e172141dd0d9efdc1eb0da16a13" },
                { "sv-SE", "27481bd1d0f2eda8f50db0b3b8ec443cd04d528777ac7ac4219773197ce7e846e1da961bf980a0c7c450253f4dff1446485b06b7c3c32f2b12cf7f6f23b53be8" },
                { "szl", "fe88b6c3fc2124220f6d3ae7d530a4f66d37f53973ed3c9593ba82b78e3f74397bcd1c4cbb5c0a5cac6038b1bc06e9b3dd3cc58b39c75b8618876d23f20ac8cd" },
                { "ta", "218f407c5bd426bdf6e762dee5c0c5741e5934355f4a0f000240a15e8da477e918f395e262ce697799a73cec27fe74b706f31304ad3f223dd426ef2ef25acce9" },
                { "te", "4ab7a5cef025c975a1b8a82a727a37966295b2e53f453cdb1b28b0b80de84e8eea7056826ce933c98eb157a6d2abdc28fdc6c131160edaf5b7512ff9f148cc57" },
                { "tg", "addd1bf92f873203bad6b485f07d592bdf593d809afe3e9fabc05b89b129fb85978da33da31c91d1fa627f133938eaed6c5748686f4a8d92ed8adf56b64396c6" },
                { "th", "8d6b23171ce26951fc3a0a4cbfb548c5fc4e55032f600123dc9e085b094607d78a2111547c3c3ec71a0b57d1feb9d3218a93151e216faf3a42755b4132eb0715" },
                { "tl", "e4a150c6a1e7c217dd2addab2fa0e0b6f0c3091b56976612b9a9ada4136bcea0cf41ca00e11e0e3e2556b87e5b135d4eedd4fd7ffef7e478e0fdd9c424fe51f0" },
                { "tr", "18ff5d8821a7f14013b29c8b2aba6f87b084e15519726df9c9d8b2f4d01acfd2ed655901c88665ff85e97f1194943332fda470f138c7bebc0d911f87f08bde66" },
                { "trs", "2b85dfcfba74bd0d5ff1e0abdb88c6ea0eb2b4efe43ea8593c259a2afbf90dcc24f9c3aee0f5fb2381d7a879efd885dcd9f9e18ee53b1dd8720b90793530e639" },
                { "uk", "d88d52908dba3909ee7e9ff769a0b3777a7761403af42667f2bde208275f0899517fc7c45237e2ed047fbc2b996eaf1451283e6b3bfd0785a406eb0cae44f5df" },
                { "ur", "82b5c9745d1bfb929bde2ea232146d13c1fff5c1683e07ed876e6449602457f71d67b34093577a74c3e59c2a8267e88aef56e175623f96e393b3306d236f5cca" },
                { "uz", "5615626448a71aeedf400299691a9242bcf527328f34daf8afae9bf156b09682729d03bf88057f984541029f627f0c619a94569330a4651c5a32aeecfc7cb720" },
                { "vi", "e92cf988009f98b1a5ff9eacad4ae26cd6752c7cf5bd4c5c1bb9d1c77c88b40929edab2755915437feeebb5b5cb4f18b02797081a63aa7aeccb5996aa016f147" },
                { "xh", "fa25763136529e6a831cc54d16eeca453616bd8cc3c979b344283a20ad9ee24d02b49ace1f12076622ee5d13206b2aae02d9694a6b071c700c9c84bd4a65f403" },
                { "zh-CN", "82cafcff2c37b487a00c357526afe68e6d151f6dc49e9e6c39b523ea5b33c654ae06c2920cd13d32e8a7d1565fc0a78eaa2afccd8eaa96825d8c2cf130ef95c5" },
                { "zh-TW", "2dc0e28df9e75d4c7bbc30adef82c014f0633bddd134440dce0342bcf5ba2ddbb92c1f70101cb8160d24e0a26439d859c330a47b85ad112dad932cb3ddc30814" }
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
