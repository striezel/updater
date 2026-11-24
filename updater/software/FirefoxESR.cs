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
        private const string knownVersion = "153.8.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/153.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3c779ad3798463444ef4adac6e165c0fc85538167c718b03cbd57d2dca570b8835535ff4fc970687e317b78cb65c013807bbf6d3fb94f8e4bcc9026a5e747930" },
                { "af", "484750b4a25b3f6b830f2b160bb78122d1431e03365e8df5fc60c20e7e1557d7ddd9a890a16c4fd5684241ac93212dd9e7dfd97aac6224a2b99e3ea2c1cea7bd" },
                { "an", "7b0c84bcca10b42b9383b7060d7a4b09c839c9983a2c642488ab496e4a88fe84109d6aa4c6fcd87888130ce86a397dec786f0a234e9ac019597c7ed19fae8d53" },
                { "ar", "49aa60ebcb1bd2e4ea387cf1189d15168b2297a6360c26234262264eb47a973b42fedba718335989a2b11625594d9ed5b329e2536b0d242d3cb5088139a51f3c" },
                { "ast", "0af441c4f386cbcbdeac4ac8f4a3e556a72941c21ea6e8bd1b8b3a2792c756e6e5706d4a030633e396ae659980c2b1acaeb6c566cf983463f3379acbac260b00" },
                { "az", "8b41097ae999f4e1d58432e26918169367909fbf6ce25a8b054fcd4154430beb6129fd06934adbbc432c3a5de96b102f6602caff244ee84758be3bf27269aca5" },
                { "be", "9a0c6a3196d0946b510de2612f71daec2ed5322881f7766a4b1ecf954fd24730be99943e324c3d23b310bdef0936e9c7fd6db779132140d42490c814cd37f412" },
                { "bg", "856a2968b01eaef46a5c111eaefa40a55bd0517d8be9ebdc6882b4159e8e0b7ba29aec4c167e918721670d9b0ad6240ff67a260f204de7aafa15ca0d5403cf1b" },
                { "bn", "9b448723028ca6b818a3d7355b95660d6fe889390f09ac7cd184eb8613fd2e27c8eddc48fe652a5dbeafcd6bcfeb6387f516498e9c64bf49319ca3729f3c1b36" },
                { "br", "1ef490c807e126fc15ad900ba097e214fb2ac33b14393e9f56322e445af5c32673da084de8c06d4dfc6188a58fbddefaa79a4430f1e6ee01abd3355977ae8e7d" },
                { "bs", "cd059080e393e4242c12cb787388d5266825d9231848d293f1be1c0a52b521641f909a37aa5c555d3f95c2ee315d04053842c30838aa1aa928969a6861d92d84" },
                { "ca", "8fbd70584243848bc46e93ea2d1ef41a38bf7267616eba5ff8aad8e862e1fc5cda495df4844626bf150200987be2e992f4efb24fd71d81225e21f95f343d5c28" },
                { "cak", "fcd22f0e83adc6df1233204eb1244164109c72f7e639400745f833700092a7978cd2a00871b5e751a1bc519b171335b48352ffa3b5820463801f22a087b03158" },
                { "cs", "9c81f9245c729aede934a1d8ece209bf09cb2beb9d4fcd7b027eb1fdd6659a52cbeba8e57a71d9330d3198c7c1e081250ff04f58e86e3a8b31e6aae466a80aee" },
                { "cy", "bf62b896404d9dab00e8297e63d92ea72e313e6e51e06f1da54b524ebdadda820173e2c69cc617425d239ed2176c0ddd953f830dda91d062cfa3e3231a84dcda" },
                { "da", "76b9f43749439427e077dab67e6082ed488f8bd2795a57097b32bda79afe5e0fa4f3cf1399e02f98346e70d7cb685986f4db253c2a20640dce39b29ec24c9ad3" },
                { "de", "36c17cbdb5332a0924eaa72d2751441653012f36b288f57dd6d4b6e1fec2f3957c370e4a672ea6cae813882b80d9b20ff8df0ba37f0e31b8d118bdce307ec2f5" },
                { "dsb", "08c930ca4f4d0f38f37aeb9189fc20cf00b5bfb3b0282129b931914fa6adc6e4a5c17adc8fe25f78a53d6d0e421f7df995899c3164ca29a072153c9cfc8ce5f6" },
                { "el", "cb17b2a3340965ac1201323b2a1d1c5f1934da16cceb2b109c1d06fef407cc16ea57da491eae3d07b49a9821c3cb7a774cb00afd4320d8173ba56d6cfdb1bd98" },
                { "en-CA", "c1b32f21aead741092019d40c1c88c5b3c8210fc648e797c8f503e15eafb4a3c659bd07b26adbfa11107b08687e11644a308fca7b860ac7c2b9386cae8a0e64a" },
                { "en-GB", "455a123230b3e27656c9c5dab0850636e53b53bc02697686190e8a3788ed22353c1803867f69c823b9fef8d901e0ef2084b1aaed1753f50fc665a343b63cc5d7" },
                { "en-US", "320ca8f6ae36792d836ff76f6bb11025a8a6a009a442194398fc76849a05157e84d8eb303a7c80601bd6d6268d0821e30551f917a41c1ea437aef9ba7a1cba03" },
                { "eo", "923435a85ea651e75e9d59dadb51870d24420d3970109321e253dc800242c0f80b2be8bd8820ee6d0c6c0a83517e4274c9b18855062afdce44d34d668b3ddf72" },
                { "es-AR", "e1b1e8df3642927c6a556d66b03953aacfe2a59fae4fe1efe95e50dd442c61544582fef55e2ac6693973d04220ec24aefd697e97e44eff315fc0aa439ee157f0" },
                { "es-CL", "0f8599222503bf7e75459b310c1b408ecadbdff132000f950a83392b12b3d498e78ec3690f8c9e52e89a0acdeee3cf952fea33e5a029ccb90870b14d550dee5e" },
                { "es-ES", "135821017fa88218045d0c6e382304219ea831ca7b6e730c39d08d610526ae485bd5e440031eefdbe2dfd7156eb2688abb7f3a162c10a3feefb5accdc2b6ca97" },
                { "es-MX", "119506d3677e238dc8b67e7fbc8f9cc4a77c77a4eef85f16e567cb4dd0e041d66275b11da128ff7fdb67d3a42858131ce63c7ab297b9a0f6ae9dc8a47aab247e" },
                { "et", "f729932ac6a19512b7723c38b1e950a0d87be5fd98a5f2c81b65a938cc307cb2e0a736f9faa71213686abca2ef26a5baef1cda9e4e11c7701057bbb4b2e88dac" },
                { "eu", "e139d1d32125ead8d61058943d93d9123adaf37ad196882286c3371541bf321d5b6e48f59604431ab0e8ebe68a5c7b48c2a6009d27e038608033628e20dba590" },
                { "fa", "17c33f9b664e8e2f64b002c7ec10b93ecf088b864e4fcab4829643903164f5095eff41888839ad3b7b2ce369ad577d23dde4ee9793da327f385a1fb77498a612" },
                { "ff", "be091946bf1d829fc633500f7777ee409e5f67070cf2151151f02cc9d3a7672a1c0b11661766daea0e2baeed6b764b128e757524dd14c50e7cdffd0ef3542fe9" },
                { "fi", "b8038c7be1db9b2b3dcd6dc76683cc40bd8d36cfac05b03479c0a555dc5077a73543aabb288ec227b70f2e8b794d91c096a19df0872889b2e566f6ff3d0b23bf" },
                { "fr", "45dd1d926ecd1ef3d221c0729316a4100d342f50283610f18a67527e5a7fb0b02b228e5a5b628c74b00ea2501770dc78891f60d3fe76c9e28cc795b091fe801a" },
                { "fur", "a1a9f1d7725bc8e0e6cf796417276cea8cf51a0bbda7e51e22660089b9f2fc1ae963fdcb809d8d61a55abcc6d18e85e15de70e8f0a23f976ca1c2b6c817efd7a" },
                { "fy-NL", "9ed130c25a5a0606623c5dd8d6be4f4152f8d1c78550715dd90e2ddb5eca00cb5d8db950d3bcc3f6b417698a3e1b92ee01f0b586caf4a777640ba418b782ee1a" },
                { "ga-IE", "8186a510853ed6b60168c02d735cc8760a86df91b614e383e091cab1c969868bad688f0bbc7aeddd04a2276bb51bce42f86040e673f3fa8190e2c4b69e2f2e7e" },
                { "gd", "43e8ee6de1da307d28007f1d76e4742653d52816e740a6d81506df6a40158c03b911a329da9882bc6cd389e550bc3c1564b4385d877545e7982ab9f7d22a928a" },
                { "gl", "cc2eac82483190249dd1185e2167cb251cc6ae5492886f202004915845c36454845ee8e0b9f9ab2f3bb743fd543ef3293c9d8d7daf28cce421ff7172b6463d00" },
                { "gn", "4993396d1cdffa06dac746c24e6e93e03ae7d44591536f1a3b04ceefcb41b1d335f512a597e2420550a55d2d30d1e6607fae1373f2c2221044de00e5cf1b6a4d" },
                { "gu-IN", "44bb5b556ee08e9fdf2cc136aa77ee49092021b9823938f2f17ca5dc3f6c6248937dc84c9478f96f91bf456b44bb0947aa170b2cf8d0d04c691ed5539bb151fc" },
                { "he", "eeeb147602879839825f09eedd2fa9738bf86334245bab07d3233d6fb4a902434aa373a181622bb19d00a5332da373092564aaf3f256c30bbdd1cf29fd0a4b0f" },
                { "hi-IN", "9bd5b27b3a9af3113553e29b82a8f2580980a60f5e80ddc40bb38c6cc74f37a01b33532a57f0b3a5306311f8d3a92517a125127a6bb61e461618ee205332cae5" },
                { "hr", "1cdb4dd2171f1e90f95c093fede91ba2a9320efd88446f5e6d098c4eac37d63163fe79964927e9871328b174fd7d1e10a4c64bf809a0247e19fa162fd48fa381" },
                { "hsb", "5e6c11b0d25bcec00a15e17dc058b20251013c847b780f4f7454fde2b820ae1f5870a6a6f91022194df17070160baa7ae9c97d240dcde674d75b627ae10ffe05" },
                { "hu", "2b560e2a5d8aa761406e9c65564ef5e4dbe8801c7a9723bee6f06417741a74975a8f2db5a4c40238dba11cac7874d0957aff25989e463b88a6cd29990cd6ed17" },
                { "hy-AM", "481f181fb7d232f0f69f041bd3049cbfde9c034da26c054bb90cad54facdf5ea36116e26d2d32038d75f89c35b297d647b132432ae2f5042049b4419c7c72863" },
                { "ia", "976273b3d792f8eab930e4a165d022c1f8d7d69f2d0ea473435df6f9bce2f7db752be7090ada335b8e60f436acdddffeb50feffb8179576675801ae603d5d80c" },
                { "id", "f75c1d2ec2374f2fcf1cca2b2ac39a6e6fe450b6027b66b575c0d152f0ec6a48c08b040a75303e4a97f343c25b50f75d8bee4cbee5f348bb2df229757d2033c1" },
                { "is", "f11f7aae410da072b526e8098da7c243d86df3ad03ee04e4252ec483c587539f9dd84b61b40c9e4c3c63eb69d724c0deca32789d58efae005634aedb80bdcf92" },
                { "it", "36a51418530cebf3fa49ee14c18eaac4cfb5167f4ac7855637ff4042f8d230cc6da910759bc27b41624feb8088710ecdf332c518c1b3958265fc16fd2e790c8a" },
                { "ja", "9dd04c7a550c1c3124ffe6bf0a7ee9eacb05195d9ada4f4430cbbbb6eb4b8a0465a7d8424008e7dfa208f84a1b257cf5b0e55788b8b14f0ee0c3f2717caa618d" },
                { "ka", "02a1f935d9463a3bf06740a6c6433d74a48d097d5ce112dc163d1eae2b6aa741e40d567064d2389d832e5d0139d6ad5d10c7f884bb08b52ea34f0633f3cc57ac" },
                { "kab", "ed2038d90ee179ae05821d6175b095b49dee1d87426ceee7b49366aa495fd47037d28dfda447c5ba9d9488bb331b32ee52be98543a092d18a96012bc4c944288" },
                { "kk", "fedefd23b728e578527abe832545529f1463eed2a8019fa5f9de979537e1dd2bef7b9d1086dfaa0071f316cecea576857151356ee2e71a69fc3074527b99d73d" },
                { "km", "6f1a413b8dc45b9a96c8554dfc1be2828788c8e3dcf0ffaf2e3d5596e4c0a5659a94494099b43ec4d98bd4e27ff8ec2b88d2c0828fc6811b563bc4175b2a08c5" },
                { "kn", "2b58603344d8ed05e4692bfeef635ecefdc165e8322e29625ee14c1369bf8d4d353ef4b9e028f16e8f76572835846e1e0edb02d24d9b60184ac31e2302510721" },
                { "ko", "59d433a8fca5ed3c21306344f6c0f51bccb4ef89573c2f2bb7a8e2136a26775d506784f31d4b4ebf364938556cd921481b2840461816cc245bc0e88f66a1401c" },
                { "lij", "0ab6f22f372eb1e8d6f4d42c279c604fdebf72a1bc1cb1a7e2be7469395b242f5b6bc55e7ad1e9943217d2f29457d88251c3537256df977220108103ec978526" },
                { "lt", "651166b961fb96c348c63bb04f93dc7c87042c19d2ebf21616f168b7040c451b3c41b07800c49402d4827b5df20a73fe2e2d9d8ee86bd6ebfc9cb5a59032c714" },
                { "lv", "9bd2e4412b1a89b3c03b959c45773943a2a97125425305a17f670d2d357c0c8ce83fb5f3cd6002d1aa09ac3b92074ceb7e81e7b00c3e8b40375f308f387a63d9" },
                { "mk", "02e19b000ddcad6f00027451e7a81ab6d235683b88628393ebfa2d854e6d5691934d14b5a1c4cd0b9a07a9d837c35a5f927376efdd18a21327c47b3172299ad5" },
                { "mr", "5e25c20e804e2cf4dac89410395fd5c1081659485e2f044558764d7a2488e32a7a84b27a3443fa002e85fa59f32f1f8e4fcc87b89091302a719f14141f050377" },
                { "ms", "71b2b601860e3c02e716bba6a16594b0ee39a358571d3098ff9cf7d9e119334bfc91c60bdffbf2386965c7d3c28b8eabc5cadfc4dde342d55b079c5575b09e86" },
                { "my", "ef9013714492092a4788a6305c67b2dd7ced409a6ee21c5ba7b75029352e73fe35a0a6c31ecb0ad072607114f691576f210e6d9f1ef9f52a456129e16fed6b32" },
                { "nb-NO", "b5fe34b81cf9201bee1fe7c5184fe488f31cd885e61afd1c751c8a092be8c37f40572c58ad217297a0d85524517755bd280563c2f04607e848126ffeb06a0449" },
                { "ne-NP", "9b482cc989223eee83c714b5a9042806f3469f77e2a081e22c0b5ec10d8c7660f95e01d2270ff02c0d545f6f4d00c3563cc0584fa9db3be86ce9114bc5b85919" },
                { "nl", "8a855108ba0684a09c28327d5582d11e35bfcdc8d00ed7dcd3989cec905fa324c2f2a037bd00dcb54ce06970419615a5286cf889ac7b5ecc653aed00a8be4444" },
                { "nn-NO", "191dc4a75c712aa2b5e2f203113f43708433f4aa7afe55802cc6de5d9c62d1ec06bb4c5e238a40fcec8778c61224cd1613ca6e12ac87ecd151e4efdaed23370b" },
                { "oc", "0babddc2e49dc74f1330460bad00d28e6163c7c758c9bbc280ab30cbd009a9fb9aad95dde70db9e70df1425be5c877dd3de79169196961791fd77ac47135a0a9" },
                { "pa-IN", "de3eb68381163b5827ab436444732019f3809f7adeed7f1298d6c19a5d6b647142c35fe014296e1f99f17c4fd0ab28b78dafb4993de42924593400c369b6f046" },
                { "pl", "fb2f85769afd44c6179f2041987ec8d1fdea7616023e444d2e2ebf84c748bed3af9cc48456a09920858619ecc3e6e513f865f27d16123dd5b7890252059f9e8f" },
                { "pt-BR", "db0ca4bb6d58b3ad4a0afec5fdee4dde356b7e8af7fe26369fe08a811b21f0068c0a614e2c93fa74a616f830dd77c24540c4e99c7e047a6882d1e000b9c27592" },
                { "pt-PT", "7e1ee96547ad67a73218c9623f8b9e04b0546974fc8f0f9551ed1deffbb675ad7762479aaad93057129904019c277546ddb120d4b42ca5fecce3400f2064da4e" },
                { "rm", "97dc416a140f09cdb5ef73f076cb2ef4741fabcf368174bd622b612a870addb91da99340eb623427965c6e075c0ce14c61f4f83088d833d252c83503170eebf3" },
                { "ro", "89daa485b8ed8cc3337400dafaf16e8acc601b5c5f1cac38796e25bb47d5a631b25995e032f6e7b5e7ef788b8cf6a525f61cb6efb8089d2915849bbc4817204f" },
                { "ru", "a387756f8257a0fb2a0038d591f156e3408fa351b7623355f557955c8866d5c16da879c887bbeac1e679e97811ca30ced1e9fac826a3dfa8408ac557f4d8a951" },
                { "sat", "549388792f174ecc7f14ade562ae9d11d4f8c8a1b4218f4a1e72fc9c996ec4f3e80cc5e5bc2a2c47dc833f89c697ce8ded3cb08310c33c38f4740c3ae09bab2e" },
                { "sc", "80df81ac01554061790ac2420beaa0d5d53fc012106c50176163608120cb365c5870731efbd9da5f1d2302fb1b60f7bbbf6df38a996d80055eae1ed7ebc92707" },
                { "sco", "ea53d987287974eb5db003648db4ef3c16eedffc435a2412accdd35e214ed9232e653d246314f3c89b359efc2ee6919d289d2e4827e3eeafe535a39b304db4b1" },
                { "si", "b5f6469045433d5340350ea76175b4af37c85159c2016ac54b929116ffd70da95a25f84f9a0be2391b9708fff813a6063af385a4380d6773b89aa957c2a2a4c5" },
                { "sk", "eec6e942434253d84810ee01d9c83681a1976e723abf0d6f5f326d1e80f7a842237e480b23177dac92b1a62290ab33d45f5c133c733e1b40f087dbe64261b046" },
                { "skr", "6dc7191011baf876a8c8ee4db02b811e6c120f6559bbd2684d7a62eefdfe29e96d30cec7675e078a9fd2d3bc51db7396a5ed91da509ef92e8e0ffd6e5631aa8a" },
                { "sl", "7507e4beb2aa48a3946041cdf5ff47a5aecb0dbaf0faee8b92fb518e0e7edd25fdd2bf819a6409863e95c205ef2a7051048d10dbf82757b33850c8b0afa9d7e0" },
                { "son", "64ca3f8c4f62310a72d017fc05076988f789a1555b36354d8a18522b7447582db742aaf217acd83f27412a03e0d650e997533849476df182c250545bf9c16e1d" },
                { "sq", "dee44ac5e58d8985abd989074a2deee749206dab97dd71a2d276a206ce568ada8ff1dfb3a4a46759a2d357a62313adf84effcd7fcad1190f52db80e91968b7fa" },
                { "sr", "a0dbf8e1a6fbd97a8eb8724e3d227fe25c9ed5187c3f74aa487679aa9f88649370136158d9c3f3ed1ee35f212dbeabccb2a70f02bc75495c31e4318ed6e639ec" },
                { "sv-SE", "af4f8d2ba623df0e13d645109b7488a73de76fe5f1191d3323bd662aaff67936845f7d949959beb8bd084d66942d07e10e727324868bedf25736c3feab73855e" },
                { "szl", "3b0f6cd76333358a4922968753a96de63d500afbab87054293d49473c23fd8096441665e685f78df6953f4b0e05f865ab5df79ae6b0278175f44125d29216307" },
                { "ta", "5b40a3231747817cfd4b7494d68fe463276a7e32e36dec42a7a35087298b9f88ff0d98b00c4fb638c82192b6684e253c85471b11427bfee59444f2dce6f3a3ee" },
                { "te", "a30d6dee7e13b2f920151f61a4d528cfdc0faf9649695487f0b6bf20f17bb3cf6a228b82d12f4c0ebea1142777ff6b67c548c9d29e34ca6ccae570ce8266c1f4" },
                { "tg", "c1ab748ae98fff57ef54c33e529ee391b699af7e0050bb69af8e8ca37b704da721c1bceab7bbde9836878e96066c7cf033f1c64dbcbfbad70d0a3cc759982ca3" },
                { "th", "0f68b39b0f3e4bf726118ba90818afaec1241a323cddbf4a001e40c9fe752bdb77863ac4a08a4d6483c094b829ac727465dfe669a9876750af026a1feb50ac6f" },
                { "tl", "75d615f6f2a1653c180814d03a83e42a66a547eb2d1d35839255b976edfb180ec9d4ab3e6240f449df3246b1260bd31bb833e40a97c5c80c2a2e4d4bcc7d942a" },
                { "tr", "651216e8fa8aed0cace40a874efd3379f169542eb55f89815c9ec5e3c5c646352d396f228effa08bad3084ebe8400664af0b3371ece875a4e9221fc63d311121" },
                { "trs", "db239e7b5756d7b07888af1c0a9d93c752d5b5a84cebba502801b6e69d0df00a1d2d465c594d05c4e94a82c075eb2c72962d1c2d0dbaeea5525ca11d0c586b4d" },
                { "uk", "87b26a5f53e5aa2ff847787f7409b8b297191564f6acc6401a8a2ef5278cc5ffced48d549e7c6026cf31c1de25ac255c0c0f5a4d89489bbdb20af092dde7203d" },
                { "ur", "7c4d7674e59b79a7959fb139f48ae0cc7b2a02c707a04f9bec2cd5077d892bb8886809c4a84d67a4b179ef07bb200f40e8ea39ee9ad37faa643d17ebef76998f" },
                { "uz", "b493d98d11cfc46dc4c374703ede9f5b6b0f7d67bda444edc75747834f127c54ae7dbcf1d9d393b22f13c25feacb5ea39ff55b87eb6c4bb0eaffe1d41a527d1f" },
                { "vi", "2551578fff669979f0557c8310e8e9635e02f0344a9993cb297afd45949f91b86d699ea35b04a7e746239016d317c273f8bf04f19d2e12d46f2c68b1a760b038" },
                { "xh", "938393740efc0b18fc2927162054374b301115798c41a03a4351ae25ca74ac3a000652b5bc2f8ce187a0738b02d6fa80185d2df0f707fe6b8d20ba36b0275570" },
                { "zh-CN", "425b13bc379e626b5ef5f41a4081141ef861bbe4b45f36d56b86806bbd08ed740c060c848561fe9e6ad07cbb0b373f62af38023a28a31d8febec08db7be4f786" },
                { "zh-TW", "6d2503ff5d23752f6c6d3e79c1cfab808e9c2d30ec171a3b8d6264fa872d1d3782797e169230c7c596870ea4ac404649d2342f38fe60a9cf03f89c34a0aab4e6" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a5e392ce7fdc6c209230e3fab8d199a4f58fb7f3c8ad96aa1016c9d2e2529a45ca65c25b84f754825abac7ae36b477fa90c3a9864c168a3781003b59b13241d0" },
                { "af", "605a8969c784b4b54311bbcf1b348888faf15a92382e5bc0ff1c34733142f25b3ec9582679a2f0a0659a56b62139ead16fcd9977da9ecda29416776bd53db415" },
                { "an", "c0ba5f1844ba8836e463c15344aa5d50552b6f6e230a4f309f95c9dba3f6a55f130d90966195cf09f6633a991fc037ac623726f4697b464289768b53494300d4" },
                { "ar", "1a768c0a03972f3b0adcfabcc0e3b98cd59283a6d52bc77236ead9e2f2ba0bbdebc7322cc872c782a3a962be8998ec358ebbd05d8fdcf3da640e48ec72ab0a21" },
                { "ast", "23875ff317437e5dbd6dfeb6dc6aa1cfdd3e7b3f01a2175adf346552fd0b12f836d31088cfdba8905435b25bf5a539080bf42d876ba3082a9cbd5ebecc1d6162" },
                { "az", "89da1d5fb9dc3919bcad89cb355250f97e7b951f9e26f2e4aa5cfe6bacac3f30246b6ad41dec272c0471637129c48b303aa2d10975dbfb33d631a887c1afa0de" },
                { "be", "252e8d07b52740eb23d177cc2b408b6dcf813bd32b11beebaf49414646ffd64735905456ae28c10506f5585ef1c0109454fe67cdfe701e11548889247fd8514b" },
                { "bg", "6d4ae4ffae01ec7aee0071af37281e4e734537017cc5e2aa80ccdab98412bde850c6de41e8d8d41336e861f0ecc162132edaa8c587c5f2f75385036e6e03f213" },
                { "bn", "e08b3e1a6149082de0570ac5db65f4dd40d8291376050a17249e24acc041062c10484580e4980b3a24045c8b877f8576eb9124909b257913c84cad50b2a455f5" },
                { "br", "27c6186de2e8134e71c157bd90c26dd30212d27f6295722a3fcdfaad2caca2b6d0313ead741d351b2d58ff95855145c71ad93ac809a8d3b52aeddf701d6cf92c" },
                { "bs", "838ea5e0808bca0858c85bdfbda4618ef006ca99414179e914ce812053558ad9efcc2061bec47419f71f8ff5cd3efed83e50d3d47bcca7d18a3cacc1a6e5de01" },
                { "ca", "f1fe463ff7b038f68aa505b887ded0a8d96ecec285343fdaac55df7833138532ae6ea3d30f2a3d4dd6e8dedc38cdbcc5d893c3af7aece7d8b3491c970d22281f" },
                { "cak", "b8a0fb6afa8572c2371fccc63052d9afed9d67a4181cece4810d9ede0f3658a1e2071dadb47e1dd5cf8d4ade52118b10a501ebffc491cd9d3d9a61628c97b0bc" },
                { "cs", "5a752d0332c2424d80982ef6eea4292035dc14f1f19d9dd90ea9db856826bc88721bc6db68cd70b33cf0e1227239460f0be5f7b316f5719a6d192bcfe2a57b6c" },
                { "cy", "98a472c88b01d5e6c5d6f5832c7853b587d9c253587bb9d278290b0d876f82afd4baaed0ff9b35fdadeec4a3a31c2a62bf7f73813eb9636b744317d1fbc5c668" },
                { "da", "4e80c2fa02faf496e4272c36d864287307bf6e703ba32048043adaffe265168c700b2b6126b9163d6ffd4ea064e86a7d00dde99c1782e14418e9cdd5a97a7dd6" },
                { "de", "3d0f828d221f6636b9d78dffe5a09d44a7b2c72e6667d48400774229f0ac77afd737c58e16afaf50e07b86c96633e753b547af847309d656db4c713f574977b9" },
                { "dsb", "8613460f2ca6dbad60f9567ade505e38e825a00d0c83ad4c7141e3c93e88f53b26568aaa9c028dc7572d6f8b09c70c983d344165d1fcc8817215c9ae342c07eb" },
                { "el", "e0db2d9f2320c2e5d43fba3c80e8cb96d010beff23e4f514de489f1f501fdaa33a3bca0639a4c2e7bed36d7c57cdbe1b1448046b81029f4fcb16e9bc23fc7956" },
                { "en-CA", "e1a2067282a64ea9ceb2dad93a3d5dbf2c2c2a2e411d048d61cec2227438fb863b41ed3c28b83c2f98703de91eee38d650f3b65a44a2b24de79b5d68c4ea9eb2" },
                { "en-GB", "6179f0422029cc4a9cc2acb58587926fe990f306bfa29dc5f28027205f2b043ee9ccc3ba6587b44f542ea3e34d470eb9e59876256513bb0f35f252dfddb7b442" },
                { "en-US", "b553c5ef3e47ae11ebc4a088f3375d08377b8a1f44fa262bde9bcb6e2ff717919b976f624d3101385ae40a86c75b984e151bc4e33bca39b39b31767406bbca95" },
                { "eo", "e6a08d49684dde1f8c3000f6c6dc2c25c6f5e9df69177b6ae0c0eccec48e818f1f4cee4e83f0e0d7c9f53ee01ecab9f097a740d5f60a095b49eae60ef6699bb5" },
                { "es-AR", "325f5daad9999edb32d7fe79cbde24f8f69fe767e89e5dfb8bddde6639a6c1813aa829ddfd15c778db37baf3e508fa1d77dbbf4999f11d43eab6a283b4fd8f11" },
                { "es-CL", "91160501f0e77e98b1a96ea0b5cba789dc4521b9cf8b4558619f83077d9cde89a7e17adfdf9fd38caed1f85b939ae8f8ffb76083132abcfd5918f2d05b605f79" },
                { "es-ES", "d14458ea3fb11d2348a34b695b62fa819c8ad72781a29b8d6e0898242dd7e932988819c422e702738763c285931e35980cb57af370fbff676aa81f2779d4d1b9" },
                { "es-MX", "2546f8731619bf6f0e26508ef28827c52247ef89008f725ceb5457acaed58ae670fac3d980ca09d1920381de903a6804fa22c74fa540d81dc7758792f8e3d2f8" },
                { "et", "cd2d0054ce0e1f2324535ed4391c41dea962e0c8a38cfb1a8a866a1fd363d7feef1874c00440a784987123de2efa342430ebd14460ff66b05387fdfdd33998a8" },
                { "eu", "39d9d5b3c8019abb5732f460ec098e047ad31285934d20afe7b2fb15a26aa6fb272cd630903d77166fac9cce4cf8f0c69672195c6035245e53e92a890e7767ff" },
                { "fa", "2fc8c74f26f02a88b463f27021c3fcf8293c522a3e6fc32f1edef6a61dd8f77769406345a5286f7dbc74c8f308738eb61434f31ce206c64a071963797ee6d901" },
                { "ff", "9163b0efd34aad56c913991d1346839aaaadc64e1ad5dbe44d0333442492b208733b6c2730419af25ef798dde493ed04ea360afa33dcd69a951171fbaa3e7b0e" },
                { "fi", "10834a33c038be33cd9addc7c18388caddaaf21ad193ff4da6a48fbf925b661642906efc2e89954ce0c86857fddf5d39e9d5173236a54dd188e50a6e1b284794" },
                { "fr", "6e485fd421e9045130fdd6e14d3c46063f2b5bbfc10e6e5b1e88b986365e6477fb073ec8757b7d2154bcf6a671e333ae7e20f4690d242a0f9a54bffb2d27f11a" },
                { "fur", "d6866de8d8dc7043305f41e4fd6563576aaaaf3c44bd733a4a02a8b3f35e3fd6e484a591ed1f9512f90b339aefb7dda0b3d06575efd2bf7d95176ef03a9e6f0e" },
                { "fy-NL", "95623dca336ca2fd8e3263c884dc31ffb6f8cbe5143bca83c3d828383bf83c04b74a2ccf6f61dbabcd60348f434bb9263680462b69a27f449a730d2c7f9e4195" },
                { "ga-IE", "f23669e185da290f4565ec5d0cded60b21094e46bef686518216de0add87de990d09f04ec87867d1d6e0480dbbe96fea7e49c789e9dc1ed6d30b1e82aa652a37" },
                { "gd", "624f27b15f11c05906bd06e193b60f3b47028b8a03ce1f77868a4609d66443da6248cfa7d66f7ddca3303a8c0e6b2feacaf67e284ac639000d0452eea2cff3a4" },
                { "gl", "9299ede3fd16f6421766654f98f5405dd8092a7f705b459b96c41763878dd428877500271798521beb5a19a0d615fc0d3962ba8c43fe297b884496d35ddfef17" },
                { "gn", "9cc47e7b6858ae4a2401d00cc247f7f5182a53af0b596105c9d4c9eda1813dca889a4133e8b98d94a5c13fa088154d81690ff7254686e93668d1468f25b1f8f3" },
                { "gu-IN", "6b9ea32b603c083288a2fac2604bb22ba83303e82259872a591b408729f0d7e4de703c80dfce750874c9df171ec60e02bbc805a93bce39c05aa7e4063e29c9fc" },
                { "he", "83a0709f09fc96c535922e7199ea491d916afcad2d60209623bdac74db174f58700c797ac8490d781ec8013a0a7a856819ca92e03eacc564891c921054da01c2" },
                { "hi-IN", "1a369106f96aafbb5a138b91696b4fd270dd2ad9b36b49cb5c9f5a014e689c5e07c6a91009f052283df4c33848f7d9c2a3481d72689d0829ad76316affc49560" },
                { "hr", "9ddc8a4ec3a638d4ebf1c818ae0aa721ad055bc6e3c17f7cef8babb72b71cc890cbb5a83eab9f1888014499344fef78317cee13a95b2fec2d1db711a6d667f82" },
                { "hsb", "d1ef7e731ac027ab7dc94f78e33c8fe6ccf754fa1636092b07f277e5ee3c971547d0bd78f4c90a23d280f36ee9b12756dfe7a272d82647c104363048afa817fb" },
                { "hu", "174a95af493c367531a25e63613156577b1336b7c8315b9c9cb969d1ed76c98252e9e7c975cb5737668524177ef21bf1efc3a9d859b11a46d9b1bd343ba65ba2" },
                { "hy-AM", "fa385769935e63948a198de406b61e1cac5a5c13b80cfb6fbee752b6af9bcb2bb5584432425f387504232026ca7b2b5a9851ab9118eae026f573b5c47d3bef5b" },
                { "ia", "7d20c13b9f2aee7f703c34c30ae40c4048fe77ba0885d1a505974b18d28a98f81b2ee80440553aadf97a373a4c242e614cfca0211a30f28189021459aecb1435" },
                { "id", "b3ab86972a0d73033d4b0b68f0582cc71c1b4bd7d0ee247aa8a62d4f08d5ac9f2143021e453856919fd92146eaf1bad643d6d4748a7219ece67da2cab66445e3" },
                { "is", "36a64c0a09e7a3561fd03fbd601abb93a512c03752829843009893837921aa2883a66dd09f62057f4db50cb2edbf5e3fd2b50dbb80ef5a409d0910bf9b377775" },
                { "it", "5c576d0fdc328daacafcc4edfbfd4d10c0bd4a7532dd3d4081ebfefd0aee3cb0ffc3b6e4dc798722477301f70ff44de85aba97e4c19f814a32e2f9195e2e5383" },
                { "ja", "470f9d0e44423e3594769dfc72141d340f924a6140fe63a23b8d0440778ebd9b6f73ad34bbc979304d63edb26c3c8b2b2da96a77a63b8314c20d34f0c04f9d94" },
                { "ka", "b90aee864c3a3e8ca399f108a02e8ecf6726bd42c6deb6befce7f494fb6c508ee47063739e79820669102cb3a050ff2db7fc3071bb91ef42ceac1703d35814e8" },
                { "kab", "6b77ce41fd88b19474f1d19a74b5edcdae983d8f4b3bd33205af9b494c3aefcfa6fe1110c2899629e6006f895ca1916efe7517de2c7190b302c17d90703e1503" },
                { "kk", "dfe5d56c0cbf45d22d05a64b8d7bd00633951ce4ca7b3664b136afe161eb067139b54bdb4d73e22c34512ad510c9c971d3ef7bd9d40352526c767d1f5adb6383" },
                { "km", "b37fec1706211cd07dacbbf928bb2c4daeff5f3947441e78a97a5c5adc709d619c954ffa814b9abb7d0e8f3c94c89bcda23d2cb8230f417676b0d8dd48d9c715" },
                { "kn", "4bada2c6ac401a0662553be090582eb1f7f5e2be83870993173e6fccf225174b0c8d717f04678225da58a805006816b356153625edd14a0ff1e9344328a052ed" },
                { "ko", "1979b85ec1899b49d2c360d07bfd520307367a84ce3945a8e1229bc7f3ba2dd8b1a780a0054f45136682611b333ae33174b7cef4047c57d63659d1e811e08e2d" },
                { "lij", "f82df5e43a263654845d5000006fe9423148a58029f7fada94b86dfa0294698ab1f19c5325b6899bdc8348abdf797c263fcd179f737c228e523e8be683adae63" },
                { "lt", "6eb98976506a292214d12e284cdefd222a65f8756cb6608b97b850b07f9d6e595544fc15a3ae3f69822c793521aa80492fb35c7c44ba14c3676ba3d22cfd9b88" },
                { "lv", "855e54babba7f7c2a8b54e6b78990aedaa06f43dd1af34eea1ad365b0b3677cb05e645f68295f32797d6191eb89f355c8da0ffb1f16a17554af291c20bdd0de0" },
                { "mk", "8f8448227fdf275af45d0c0bef929a2136108a795b6dfcf026680c1ff786ee9ed968e813583ef1d5caf8a44bdec3198e83bc86dd623da794f80f82520c989509" },
                { "mr", "6fa745f932aa03e28b1c52fbb16ba86a911a1cbd36cd1203fd715e55af96ec8af54177ad57d24268ca82e0a0eae1848a335c9adc533a60f300566ab5a3834c95" },
                { "ms", "e48179fa4b33efe9decf8acf25107b3e2130c0d3807357625ad1d62e573a5b1b5af6d8add1a2fc5559ebb0d8e32b296754b5ad77bddca8963267317109e27342" },
                { "my", "7f59f2acc036cd64edbf7306641b6544218ffa17fee0ad28890ffba5b860e5132afdfbcc94f050fcf3efb8c72bef16406d42d59464341e781e4685340943b467" },
                { "nb-NO", "21d06fe62f811a175a111be2461a8b6b402cc75a61f56c957028e299884a3bbe32f99011f036ee678b884bc2b2bfad0a44cf02741b82199f3ef26809ab8c90ed" },
                { "ne-NP", "8bcf2d79e6e9c0796a1e3d383e0a1be1380c8bed91e06a8eb918e24d5cf88086efe9a88b35fcb96b94a639d8bae8b653e694f05d077b5e8652243dadaab8196c" },
                { "nl", "1fbcc9ae8985ed897d4a15636ef49b876a9a509b3348568059e64f85e6312b4bc5aa64bc7e0ef8387cf20365fcd99cb5a3a1ccd3d6e11916503e731c8d043c18" },
                { "nn-NO", "0a2f656e7c8a737bfc1a63f3ab3f201ae4ba656571838e99a47261a4877aa16bde6743c82cbdc0d1eea46d4b5f68d441b2e81f91ab8bee08877c0d3eebcfe1ba" },
                { "oc", "35831d4142b531cb64d9fee4c925a86c619513f7283d7a484d5ad7d5a9a4e811b16c798f8b17e99d38ae454f3f884df2c1c9ee3da0a5e651a31105f623835ed8" },
                { "pa-IN", "c5f773bd796decb19cd4f2941c5ebc68f14fc5f4284b00f60a1ad7d4c3eac9e8398a7effb30e9a4504dd92b4fbea6ffe0d46f7dfa1d701919c2e5909b94659a3" },
                { "pl", "2a508750d5168184e4c137dff3d92ebb65f0e9ca28cfa5cdec2a06742b02ff2c5a38cee045ab460289bd3380a157b44efc664964a56a4099698fee377a493500" },
                { "pt-BR", "304aab049da4b94ef75c56764abf7926ae2bcd4c188bbdb0d8513cd88ecdcfdc79b3665dc59a3158e28bc19d3a756050afbe6615e6c0f2d1f5e8e1fecc54a67a" },
                { "pt-PT", "f8a1648f96a684ea4654d728e2cb588a28897e874903d808b8d84bc5e0def29c491e6939c62df2b3ab477475002bcb73e8ac3d47d0e711e932ef290d2ad0f408" },
                { "rm", "faa3d99c2fc76bc61d1dbca644bf761d6e80e9539dad6fbc915dba07801107aa1326fe286d2a44119afaa52168266ed721e27aa2e832106fe45865c5f1faba09" },
                { "ro", "7a5b8ba535e75c25811ed05ddd35c37b53be51ace460d6fada7371e73ec940d444d759aa8234fc3b5ceaf8116ce7601e1c2d127d3023e51ad530d7bd31b8c38c" },
                { "ru", "d7937ff4be8854e88e0ef7a5624b35c9121521b596bca88879ea56b5c0e59c216cb3e298d5dfb6d61620e3fbb8a7ea89b15b3b2bdd455cbb3c67582c5bfb5c48" },
                { "sat", "2086fd7ecbb6052e16683c115c0252427a04d66c0cb39c8a627ee9ba32b7b58eccbb3308d127b83dd61d7bdbb2777f7cb4794a1b4f10c824e2c8af042578a357" },
                { "sc", "5fca1e34d55bc553100eb4d8b66f9fba81fac31fd063cfc7528d7b6be4792ff97e8741d061cbde1a80f35549c6aa7039cfd8123c7fe4c3024b393ca8c57f582e" },
                { "sco", "953755b42d9a5c6e2e8e013973ee49335fe6e3a6d49afade2b7cec9a2092fcfc3889eee34693ca9db61afe2872b54d9681d7039cecd772d49d6bec0078d3d566" },
                { "si", "6b59c43f93d02d8fee6b6bc8abeaad16b1eaaf1b1b179afa1414e48a60ac1d9abbe84eced941e177632b9f0e393f16d7f64753e06ff449267486de1c878238c0" },
                { "sk", "8b61f1d6f4e3409166c9df40e598377de2c28579e6b46c46f234322d0de8dc632d5a09c06fe919b1a94532b23e53064bcbb1ab8ea7249be61b9b4f91d22692d4" },
                { "skr", "704a5f34f9278fefba6b74d7abe9606e7bf5eb19f036b710d3175daa5fdf0d90203a0da6d9cb7a6616df63637d52d391e355d82dde9fe05053b54011e8a2aaaa" },
                { "sl", "1415095ef67a2ca70a6494c73abab2ec1ca749b3a91ebd1d3ddacce8c1d6755c3ca916c79c4263b0d31b2cb3808767f4c56ade2dbf9d6dee0efee57267dca4b9" },
                { "son", "4480764777afeca5c8d0606d2d37c37b73575c75c534983b9614718d447180305abb81a68e257bc5e536daaa74a222e0c136f68625f02f4c50ebfe98340324dc" },
                { "sq", "5bd38c8e522b37e98f7c3cf8deefff11003063aed7f2bfd79ad0756a1bb4980c9f1a99cd28217ff8107596b5c534bce5ee9f844bf8a922f818da8ab6f7c85601" },
                { "sr", "453365e0f7bdfeb295df16be5573e7fbc544ae45ee554fb00fcb33d246b0e89a6ac56d325f9d657b55e5c545dfa9644e7bfb7db890a830b0f2ce2392331acc89" },
                { "sv-SE", "522835ef74be556baa65fcb8590bc3e4007a9e9c3067be5a04a4f8f3e9b5c1a71517343d1481b424e4a82e439c8d6a88cadda90217aa09aeb0a67deb33f64b68" },
                { "szl", "e5305d29c56b06d6a9a793dd53eb700f51edf095f114e915f6811532978c06f3f78e0eee4c555eaab2da17f5560b61f9daf9309221ec72001cba14b9187e38ea" },
                { "ta", "c239598b877e78f466fe508a548e5e4e281a67fa8b3b276cb71cb938602fce88c9cf05b8d6984e9afe70d281767646111df747b67c698f8be46bbad3a9cec427" },
                { "te", "7615b119859ca758133a3d62be5c66e8c1bc1aed77fa4ea84cfc896f45345e2d04a48ad6487d2ad85dfb3da2fb6be7d1468472f6fbf92ab3ad18e1b7c91a5cee" },
                { "tg", "299b02882281b0a32efb1662ac252d70936c98df380334450c3f865e95fafd2e2b700aba6c1b387c6c12c5f2cdac0616d5b97b4a8701939ea5ab3726b3da70c5" },
                { "th", "327fd24db7a481ad739c4c404c77a216584a1164bf12fa97dca2ce6038517be45929b3fab812c7f79ffd41ce9a4de5284a4b3508d5e27347951b4c435024e9b6" },
                { "tl", "638ef78e31a255ed3d157cae3e5d3a1d6bd431a9c5cabf0893c013b6fd7b838708e6c48ba01f2fa712215cb732da3e4e1cf801deef543b3cb1aea2842c1d5e77" },
                { "tr", "d9613d05a9d86ddd4cb2d086d7b9fb5a83fbc62cde4254828de785d6f530efad0dc9a726e68e8c7bea1673e58520d9339346e2d0ad6d172cac42ae94ced7f6a0" },
                { "trs", "b536357860f0cfc12cb33f9337458aebf763d14d9a0043784ea13b86799ff2a2fab2cf80d5da53eb0a3dfaf4e1d03f9612a6e43225261fb003b2e66200214fb8" },
                { "uk", "d7705a0ee4ed23a4868bc32f74219b7d0fcbe879bb3da6b0711ff520f00a91959cc0e0f8d167d8a363bddf8b6863fe2801b6017a57d98d4d131c0df71a26847c" },
                { "ur", "c0de7eb67aec6096757ecb9b5ddbe21075ece85166b8f3ed2433d7c2da49854f339e62483282d0b1518a6500f750a7a7a2319c3293d94722b3b88d22d02ebc0d" },
                { "uz", "8833d67eb2c53239bda4456470ec516489f19a0a8b1525b493903de2713205f8f3508fc18797fa9ae1d47aed80cd76deafd0c096711302bb7b1901ad6d14fe0e" },
                { "vi", "7062d34b22f9f59ac156be0956a280c974220bfcbc32d153f02dc447ccd33e3fa75374cc4eb5d62f71a367f8d51256a42339c6270b0cbc1a96ae01dcfead20e3" },
                { "xh", "be2a5967801a5e409fd40b2a0a83fb6bd57cf2d1e04a6ad9f19cd1063a3eaaa7bb61aeec0cccd2e05f2edc17a57516bcb9ab2695572ec953d1d398ad2607ee30" },
                { "zh-CN", "0f77b9c3aaca9341f37569a1ddbaa06c49bcb033ca39cd238a3ceed9cf5e5e087e3699188d1bf53fa4544ac232043bd2ce8c891f04939620f2505263afa02331" },
                { "zh-TW", "088bc1d4e057b0dc714cbdd9ed99758bad5c505587d563c6a1decc3460852a4d2e715e4a31e3d06eae0ab2db865d9116db16c4011e40220b1dae63b95261aa7c" }
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
