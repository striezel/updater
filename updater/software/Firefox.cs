/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);



        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/54.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "04f3f47b33fe58a604d27a8bed097737dcbefdfcd0d33b99cde048d0e2c995d0d9acb7a52ccd20d270937ac1493b64eff99185930cc91c941508a5f7ee3b607a");
            result.Add("af", "069cd2c906764873263f8e74e7160e5a4682449b60ea850ba0a1fdef02bd9a84ece20ef6f560f8f2c49010108eea61043f4ca106bf4d695cf81bf6955cd93a45");
            result.Add("an", "3c505e467ee12b257f109fac0e65244ed84f03f54885d71fa8df724885e5711615156d073cbb911c518ff36b5668f1c6d73c53dd1dbfd1cb31475c37ac402c4f");
            result.Add("ar", "b470691c7d83a54edbb8a22a87fcca39aaf4723d87046bbeb6e2ec406d7e828ed64e99bef577b4d54932cb0e76f715f649cbff441087c27ae54b1918ed343ef0");
            result.Add("as", "63ce7434e47fc5e34e2e27787811645d864dca2e3fecea7bada3f03b239ac425bf038c43ea979a457ee655efa20f61209bdbccf4b5a3569f1bbd97a88727b586");
            result.Add("ast", "df3348d8758adf54de7f9cd85946d9dcb2871576ab61a6d321a93d472c7d7ec194d8ab7bfe9966bea3c1822658776d578b0a460e99f7b997cee8c7fe132ece5d");
            result.Add("az", "8aaf7881c248db6c38a89c608e21eaeba8aeffb09ee00a5ac7fc4c0ff6cda9a6d4e05182e9a6bc2fdc8f808ff74e456d2e84c676205adfcae9ab696ed088dc83");
            result.Add("bg", "13145f7d309813770d269bd21950cfcc0b8e1a80bcd04240dfd1830d900134c367b2eec91031c10d9b9c6562cf24065660cee027e223ac5f2a1d54fd4bebaee3");
            result.Add("bn-BD", "9e890d1ff5feb2f88a810913995c63a69290a70dd9b97e9f8b0555d6f317be9e46a326f7ea105cf4cb6c125759a0a05c69aa0951505392c7fab848b7a0c72a31");
            result.Add("bn-IN", "62f270140520c19360dec3634cef282cf8bc7f41dec5575c461a3a160255437ad881a8e00f132ff7f75d45a91f79984171fed96f6ae4e950672447ac914c865f");
            result.Add("br", "5eee0972ce05807192bdb58e330c3c87f72ab9517cb141279eb26842747c6541faf702ae116085aeb95098504422fb3f8c1bf3fe04b1f1a7d73b949bf56ee917");
            result.Add("bs", "d7eb339c8f075bb8a12ed2986bfbe9f75e1b4ed243fd218f997091c8e8f135c4188ffc9ad4ad480f1aa18605d2054093ecedeb24705a83269904cbbbc32b179c");
            result.Add("ca", "781fedc7dd072d497d05ace2727cc25247a98dee0bb66a265ed2fee35b66e7cbeb32805d6dfa55f7e09788f3debd34674b8147f07cb41bef8078205adb1aa4a8");
            result.Add("cak", "d48a7b11c3b7d888ac7a84dbe81379f6bebc9a4b58e0cb3cc357a85fcb0ae89e7fbf3233e87ac5471c79bd11c832393c7afb046266e06b0ca8e31a52e696e84c");
            result.Add("cs", "a572013aace27873a5e3350f6b8e05dc0fa6ded692cbc42427ff5c75add1e4190f9d10422c1ab8007832643c39ea13a4d9d640540d9d0d892b0726cf28e2ce90");
            result.Add("cy", "420e878669dfd8567087db182c5a88d69fbb6fa248ca47cb1e6830d65dd984fc36a79054c74aa0db54e23af7a78d2cc4ef295c2e891796ac5d58430429ee6924");
            result.Add("da", "2a022d7770b04fae40a585c2420a271c7662bc862fa03312bd618a3e5fb793212ffc11db9353eccee033d4836585faea969f39b069caf3b4097202c56640a064");
            result.Add("de", "2546509d9c2e373565d230bcc1881fd1d1fdaf6eb3e3a8ac2f5a791a173f38ba59b8be18757d2bcb1ebd96ff70b3fce2c76a7e89981cfe7d97044a710a1add9d");
            result.Add("dsb", "6771aeee12b740e28f527f8589c977cc7b3ddf777c979f4e8df0a99fb68109814eb029986328baa661023bf8c1cf67c73745728024eb680f43fbafcfd8144760");
            result.Add("el", "22643b786704254ee93041e8c1f1ca7b9532c72a37de81fb9091d82a439860e322e65658a4e4ea7a538947ff62b61fe5641051e0c9f16c18a200166dcdee6efc");
            result.Add("en-GB", "0781c8a2f70b65e9d23b015d67a85697787c673e44f7ae27f7b31ebe3ff00145e50b8127f8c3645fe4cb3ac46438b4b6698f8a58f40aac83e635b2258bef0f16");
            result.Add("en-US", "0750c0cc47cf6795fa4acb42c501035a744e0dc6f0dd0954343ad90760ce2769dd826cd8b8051453bfca4e49c6bdeacf5888082e934789fac0986a7da3335070");
            result.Add("en-ZA", "ff5263f4bf9fc0b3f4cc2caf4032cfd61f3ce7eb1ae4dc566cbe490c9f70b21e9a46525ff2c064b52f9cfd460ceffb334128c7505d3461e02c9fdfd487247cbd");
            result.Add("eo", "5fd99adf22c6d4eb5e48198eb435acf3afa67b210e51673de5cb5987a8a4701d59debd176f13355ed29248ad82c3b776efaf821c03f46c3fa92a56a5f4afb9dc");
            result.Add("es-AR", "9ddbc4b1a2acf9f739294ca1cba43ccd97c44784df9e86a2a7be098f9ea785321782ca6f09818994b06f5aa3cc232ed07eedd38463534cd4e91ceabbfa17b22b");
            result.Add("es-CL", "aea55f3f6c2ace4c3523e35698faa3639682e1cb430edd509771817fc712b5efd5df9e81f113346d793b2e32c94d46034474e6368f80de9e748cf3ac3b258b56");
            result.Add("es-ES", "5d8bfd7bd65417c4baacb8fae893a001afbe4cb7f477b4528cdd2750fa74093ab00a1da0f3dc927e90a92aaa57673be33ad53847f377b3e88246b148ed51ef72");
            result.Add("es-MX", "a9725f788c9bf109258449cddd4774b203fdabb04c7c26e089c0693ba39b93d9094e33c339f97fab32b6c1d51559093337f8295bd888dfe161eb88d280c81848");
            result.Add("et", "d2e4423424066e63525900e993d4bf0a91b2ada8729acde9655fad81ed8ccef140ab4bfc08a1ba67137453974369f71252d3fec36a88d0814e7e26dc83feb207");
            result.Add("eu", "76022a9a1c41f19503afab1aba16467e88680d53832cb5a8ecd1635e545f390b946cb1a37e1aa89bb369104c9bcdad56059f950cdcbc5300cacf4ccd528719de");
            result.Add("fa", "447c1b1107f43723256fad440f8e6f6a619c6a92b2f803e8cd1bd15091229bd0c8423b1172489b7d6cfbb542f3917162bed06fccc69a7581835a53d3ce11be12");
            result.Add("ff", "f5f9390fd45363e0f4159f2003d3d0dba4809544a16fe095f4052321f5595916f029683f1d46ea19c26f63fd673c0d83292dc39e71ddeb7f43b0f34d365c457f");
            result.Add("fi", "a285fe0f494f4ecb09310626bbe285aee1ea57fad7bdfe6424de2d049eeae22916a9d9cb5781f5ccb723cede340d0be282a53c8bf03fa577e1d8f0e1e79976c7");
            result.Add("fr", "9c30871e9ede50537a7e6aa8ca1e16139df8603d92ea7d4fce11a6b1793bf3d3f9ee26134238c8272654f566c5609d23384ec487e34e59e07356eeba0199597b");
            result.Add("fy-NL", "3c667b446b9c7e259adfc2f7e35277db04b3dd7f89de225f07844f221147418d02bec674b94fdd4da2a5bed996c5169b7e5bd88fa7397eda75355cad4ad3dc11");
            result.Add("ga-IE", "846569e8fb0e3490a9f06f3eb2c6d32a8f542b8b8ea7a67fe3b28784d0d59d18b63e6c1269aeb3770bd464891cf34f23fabfbf214d44bc857b0c3543083681fd");
            result.Add("gd", "202f41711067e6a50c089e49af2605abf85a50c68055880e9c8cff5b019943a98ef017d1b08d809ca9d12317f09cf5c0ae6d77342b1982b8509962071a5561b8");
            result.Add("gl", "61c95194ff8d0d9294843f8a77b2b6a5761e023847a27467baaca574091c96f1c9cd8939d2568ccd29430eaedba77e56cd94db6be5d476f9cbb10a9cd630bbdf");
            result.Add("gn", "53906e0c9b0b542ba1bedd33fc19e29b5ae988348c2eaec190471e835cdadd14e10dddfc7fbb9a210b01c2f95e77df2af36fd3cce21794015fe4a07387cb9704");
            result.Add("gu-IN", "b844a0ed5570cd3d5a071fac3eee6f24be3079fe324c7874c848ac1d7d8b6bd8eb7aee3176e67a1cc8c44c97b264d8a1cde96f4a1d8cb4ab756e324eec993658");
            result.Add("he", "ecc186afaf8128c23cf54a894f5a167ea6d394cf1ef406cd76ef09cc5225e10fde860b3f377b8ad805335f6f93d08d82ae805810bceaf93946ab3985db04f82e");
            result.Add("hi-IN", "220759ac46b8f08f0f8b76d5431e2b7030d11b841a22a04e1433702ec0a2a0642d7c606e72320bacee8a026070ab18520d2920914001898ed2e257686da7be93");
            result.Add("hr", "e7319aaaa6353052824a0822da1188f44f7bd842da616600376e063f26c39a566944e5f94e865380054517d29134e99fed2715d81e02a56a8cd2015d0b18d26d");
            result.Add("hsb", "6bcedc171ba2bbd78cd673c313db36c1371c4244d3724a35465661721b2c0454299dd1c48faeabe29378f40fc3cdaf4d15fdbde4160612cb9d7da20331eaa207");
            result.Add("hu", "1316dd94e9a5f457a80330e901cd18644d76d7bf834b65e6a206f11f56696351331086a6c580624e47a24b5c10a46ea0cadc35361b7e9e734e5c50f3587dfe67");
            result.Add("hy-AM", "67c6f00e4188807ba4be6e65ad6a44fa991f09bc08a8a9d387958d78373b9a9647ee35945159412e9c7ffe737157b8a18c440c18210b083002920aa9e04d80bf");
            result.Add("id", "1f0764ff2ad79dc910723749565d2ef50e4e01b92c3fc6972e2a19586b97719d0b904fb15ea77ee39dcb6a48d426df047174617f41d4cbbd01097b4d3f735141");
            result.Add("is", "73cfe56b0068566b14f30326d03f9a5b89218fe96d980973005390c88b1ce8c490fa2b77529a55dfd9dd31e62c67f11c642cd2e416127240e52b96cec0a4ca8e");
            result.Add("it", "3edfbc415908987fa61655ef5e1989a1a392990ce828a67a2504a16de563d7d919f3351ff2657f75e5e195fcd281bf1fad654358065abcf97fae6f499d2f226e");
            result.Add("ja", "e2c416c6a18f91e8e1ecd4bef070d19ba2ce5cd0ab0955965abb68d65640cccc7cbd0fcf8db397d4d87d1f9a009d5111dcb397253f3e9fd6d7a1c055787412ab");
            result.Add("ka", "836e958d4459bedcf13e9c111615dfc233a7558adb4e71a318a558e712dde9d59acac9b45e93c58ebeee04e445cf8d1b5f63d4ffad8291c0b91c50c5e50f37fd");
            result.Add("kab", "3e7abb748f0f3afd715b81bb5341b23ba48a69a4bc221b4b5b3a821ac70376846266d4750baa13c6e962d7b746d007152fd40c8227890377cf719373ca8a7ba3");
            result.Add("kk", "252cd0d943eda7c052506e07088d1d14a8149a18b8e58f16cd17405e4ab0319f30f11a5b3df72f7a3232aaeb604ff6b356499e1d47245663cc62ff71f4ebe97f");
            result.Add("km", "5a94553a13512874e680490ab66a6f6c49730c606c5d29d955b3c86e80523f68bd9badb4b324cd59dda7bd73f7e530e75851f6363c956c412c4eb8ea94bd4978");
            result.Add("kn", "2653529c8d17940bf8e357f1203a864672565978eaba578d9a5ce4b8feef5603afe837d49f63fb16b701715015c8c609e55891c6ac4fab29a47823a7739c2d71");
            result.Add("ko", "981f5684a4abd351576b7ca089fc2950ab69bf765ae6ccdca96c569592de62e6f5d809174e83e4b7d78acf5a78d3ff8b20613cfd1e18c885582b5fac80f58efc");
            result.Add("lij", "238b09b46d81703a2aafd1033eb5d6cfd5dd4f6f39f4e758b480a134e0362f8470675053c65925449cd0b593fe39b95b5e79c9dbc2a23e773885b2ba7d09ef2b");
            result.Add("lt", "530184ae02fd3f602b6efe584959e8a6c611d85df75332bfe1767499b4fada38313861b436453eb85d773074ee2f6f7772a2faf017f1bf207aa46abaeafd337c");
            result.Add("lv", "3e247959c462a6f154116395adba53cd12736115610866a7a04c631167c914edbc50c7bdc73bb904a4cc798e731d546770c4c02e3af3d9f0bf2296c6ce844076");
            result.Add("mai", "1425e3b31e24e468c4f74fc494d7ee1864b64203ec1bce959edbd371482c05e1d067700c49da9b0fc1ee1165a0c61291ace9b6dd57695d9c73c8a8c7f0a0a2db");
            result.Add("mk", "853c8f9d06693633b1d092f1d06c7af7c66e157f016af9adc916107e2e234723b9411bd74cbb687e107acd0c70a4837320ac0c713f3515645513b24b95b79486");
            result.Add("ml", "6c85e0ce7da14f44861d9367ab0e7251a768e1740a3446d856b62c8742a320d334432212e131dafb161705f67f0766a2427b0f30a356926c49899f77f3e854f4");
            result.Add("mr", "c3ea4dfcc17aecbd347a0a8ec7126467d23e4d5c0d63d8ca38fcb851e7faa94705619cb44c83e098b7c806ec6840c62cd8fdfed7924ff9df681ca98ec1927856");
            result.Add("ms", "ae691e28fb742acce3afc4819f8ead6581cd98e9c703ae02d42767975fda558b6357a0765315f170e92a7720fc79f4b1ad0862910e134c4ec1b63404b3b73290");
            result.Add("my", "ed28e0bd14eaa2f64b278e60039a23f4873dfa488a4c398bb569e96ba5a3add43ebdd98a8f8c37c9ff603ff314edcade598a1875a112ab1dcd6bc385fc02bf2e");
            result.Add("nb-NO", "1c3b4bd677f3438a43da8a718da0c65cfcfedd8102a7a4910068423dc0e0562ab47388de673c558b4721de0a14c6796871fbce32cdc9a3e3e30cf7bbf1756bca");
            result.Add("nl", "47d5f9d6428057b870f905536631c3b1fa5db9938a1a59b726baf68b71483b420673de4f6e6da5810faf4424aa7b0c24818504215ec354eca743e67f3b4f8d85");
            result.Add("nn-NO", "45124d86210e5fe5b35a7d93d0e614f402ff20e3d731dcba540fc2c2799e9ba71ac2592cd988ac3a036f20d37c5bab932f392d18243900ec1477e6aab4cf8745");
            result.Add("or", "1ec6d28ca6555e81813c4dd1ceaa628e6c12809f4e81fa13246da7f17b80086251725b4a5182d1ad783ae787136b8fbc5a86a71e6713acfa43cb9f0f799db9bf");
            result.Add("pa-IN", "c257a7fb9eeec0576ad14087767208e8be6ad5dab36fc5aa60cf834505aa25e85c355b759cb83ccf7948ef43b64fb4ef74625b1042ef6583b3126756d6756891");
            result.Add("pl", "8a7aede6b528a4f73f967260a4259ada937573d6252f95ecf0970144078fc53758cdf210b6d0ced3244766ba90594a1735ab508cc3f49789d3379ce7dcaa0502");
            result.Add("pt-BR", "ee396da4af77f4d4a4cdf095b298c2aa728dcd9cedc8da5b389bb5e6a53a4fe3a5d0a3508448d9e997a304b707481d6a3a007ad601863f0ccc0a339125f3e34a");
            result.Add("pt-PT", "204567815da2d36eebf4947eb7a883e180db333d5c52005d6cdb2548a1d1e8694875c190e5e8b2e980f0fdc179cce742b14acaabe09a7614ac5e0b488b8e2307");
            result.Add("rm", "406aaa5be132b995ff0cc0a7e25fac77ddf1f91248fbaed43fab9b215cf8803ad3228a4fb6a7480f3386711c62d0a6ae051a3c19481e0f0d789d0ab764f220a6");
            result.Add("ro", "04525669fe784f02e10ec3f54b398beafc24e83e175efceb26020e9ad48961dd34ba913e057980a9a8a01bba6db8e3276f617a3316c665bccdef692461e51f82");
            result.Add("ru", "f23636429d73e512ca19008041bb76220307219e1b854f9bd5f921c3ad7fafe2b552e3f7295ad70f23d3196cc9449514cc756e6ee29b90e2b55f904facab63a2");
            result.Add("si", "ca682df5f0420abdd5096878cc034faf214b3a56a81ca4d3f03e4f8d48d8f59e250ee155f5c68f58b2a24dd8be8ba2236c0068c81d3d956f48b15f84c8226b6c");
            result.Add("sk", "fe566c17f7219609422679f647609ca021349c40398af958e0645dce793a54352b6258739f7bf6610d5e5e87584fb6256bfa733052090dbd0a2446eda5071391");
            result.Add("sl", "7d61eb41755989f11fc6d6e9f28d46538410b55129d9643a916abc77c593d35456f113744638841fe199eab16cf8027239b944923e55e3cf2a5b2074a3769d71");
            result.Add("son", "0a401603ef169c7775e4467752594d5f2638265d0e24aca21979c828581364b6a1ea6d4351f153bda799b298e9b36772ff1f54eedaca98371972643f95b0f0a5");
            result.Add("sq", "0e8b73adf78c6e335005840b548e926107085971fcc75ab68ae6e9d187822de680c0c0f982c7b7bf2c3889ef24a75fa0ef42f7d0702043d0fd52d25578429ad8");
            result.Add("sr", "87396670e831d7e012608919ccf7eda1fe98a13f228924ae74ceb0d2c548c7884e72224f1e103dad1f6a85396baa7e7a4324afa322da5bae0155ccfc5f2b38a5");
            result.Add("sv-SE", "06a442343bf1ae8653b181b0e1b98a72838d2afcb831711e5c173f12ef89f525d19ba06d6791d7be2ebe5c9341b02c7f4b2dfd49af523a98ccd5a365efe78218");
            result.Add("ta", "0cb9c5d5ffd88bfc6f0f0b6eddf7c5ce9d75c97ba688a18aec6a317be128bc45c6b311f65dab193b9c3ac5f995cf5dd887144650840987d9c524797f3b219d13");
            result.Add("te", "58b91db27cea87255cdc09a92aa1fe8e5cd35621f80934beee701e551fc17f5f296026752bd707e42011506b0948fbc9083659fc4732431dfb84a3ed7c963b9c");
            result.Add("th", "e79a16b5014674d84a74288a147d544fe89bd0fc9dd78a585bb727e32a46a5a89b201d0fee98c0b19adf4d34bf61c543093780a49b459adfaaa390a834ed6bd4");
            result.Add("tr", "9aa840f711593dfdf2a6a422b9c4218a03c28e6287ce78dc52bac98495a995871cfc6bfa041346a7219e4ac53e2dbe44928bd72e9051d14438c9e6652b531642");
            result.Add("uk", "72aa7e191a8ce47d75396701a7b9edd969247d72e6b38fb218912420155b4447cb19a2878149f27def95677ca087cb0e546fd80126f273186c2e74dfefc89847");
            result.Add("ur", "63747d45049f9a0f8a0c08e6060346dccff34a6016a1e03bf225138efea5e3d82136d2ffccb7abd15ca31e6c28818da49420b4d9e9ec0c7f7fe4b00b45f7b139");
            result.Add("uz", "ffeacf32fde3e760bdd937bad1d124a970dec118142cff604354b4779de74cdac27cbcbc6e1a980f32ee34faa0c3145376c87d406bf41c6f9d0292245417868a");
            result.Add("vi", "57b8751c89e4484b2e636fd9651c031ff1ccaccc84d84a94779896e7ef4dd18fd30ebcce60bddb61df73af5fcb31c1832c493b108194e2dde6f651e017db7610");
            result.Add("xh", "f9714c5788ebe41bce054c4ea9cd57af5321ce4d70c1cf81026e3b2d650f4904a7018976098b0bf0300f3e6236ed8f4cb6f0b5c7b4d3ecbada73b67dac43f5bc");
            result.Add("zh-CN", "8552553338c2918f37f2bc8482c2d2dccc43b63b0e941f8a533fdadf747c63d2eb341faf5ed0146507d0f23818c94c76c1d6bcb74ecbc837d1bea1ab3b770592");
            result.Add("zh-TW", "fe58dfabf2a1af13a116d557136fb49e13fc5ac2d6270e91c01f4f77afbc9870e01683791b0f817412ba18281d696f5ed07cebc94583217bd8c1f6aaa2ab8355");

            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/54.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "beb12c7b1e21ebfc998b99acb789476d6c2d88b56fdc8646cc3868c69a2a6607e3515ae197933d2d29bac8b320b332dd1e62f3506816af8fce040f954a5feaf8");
            result.Add("af", "6195e91b8927f92d7f7fb102182f340048d3bcfa8a69289349c9311120aada6185e9faba3e121593d639ef8cca28eeef41ec76d33cd5b28f1dac88d3dcd65484");
            result.Add("an", "912ecd178a812a866fc0f369fae5411f34e8133e01c884c26a49a421a456f010b6fea20a2fd30183341d6592d5483cbed93ab7911d7ddd473ef1a69ee23f5d05");
            result.Add("ar", "4dabd91a256b30145cf6075a4fef3e8f9ebc493766ed9b3b10a1cd86cbb2657938e8a4f6ba2a8d33e45a619a4e86235f5ac66bc00a03e1064b4d0e1139998c09");
            result.Add("as", "6652522d76f6359c4073257bccfcb86c0a1fcb669ae7fb96e5d3103beaf742e061cc0de34d3654de0dc52fd09bcef5fab4002493052e5200a361aed5408f226c");
            result.Add("ast", "4d83800888e6f63bac4afbba195cba4373294ef566a9fd72cd6a6bc44f0742e1488b5966254f9a1fe4927a88e32e0bb79f3cdb80ec82d831f7316ca0a2fecdb1");
            result.Add("az", "5bc9a74b623a507ea69e025da53d0bcee80fd5f315c7d120706ec141678dad9133e970db2ee610a7e146f45191c8d8cbe6ecf21551a40293c8bc2c6749fdd63e");
            result.Add("bg", "e40ce400b110cee81c9c144e87909258640abb772de2e3f063843b5bc2a6d99579f9cb1da184fbaf1face7149224bd82485166f8bc6f70834038e4afb3b141bb");
            result.Add("bn-BD", "ac79e2e1a28e10bcf2dedaae44be5931fff20cd2cc76e55a93221e5f97e89e9f52e9c24ea1339a2535ee437a483807f239bbd1b74bfab6f6e62edd9f9d975b80");
            result.Add("bn-IN", "d21f92ff742a4dc4568c5ed34345dc66bc463928a76ed17e6b925dae6392b83664c1b26b2dfa6e5a704e00ae40225ea5d212b5d26ad938bed136c95a137e2b19");
            result.Add("br", "f7fdabac80c2946ec889796b63e2b2e7255c6888bf663df9d2aa0fad142c2b6dfbce51aad29debcd238567a403c1669bdd195c333fd6b5d5008979b8732c940c");
            result.Add("bs", "e8c941596d4a6e3e5cd37838e76253a2227f2a579175b3974a5c140ea61706bfd934c9ee8ee31743786dba6fbdc561406fa5e424345b6943539b267abcd435a8");
            result.Add("ca", "fef79547487032a0fe854f5be87aee4fea1bd76a2594bf61b2c219ab9792e00697cb718d16e540782342288b79987a533ec789cc6d8dcdeb0101783bb9c3a816");
            result.Add("cak", "48c97b114dc288ba8d3d96acb76fb3feb905893415659050b352f2021886ac49e28a622b508f9661dcdaa42dc43eec47e9f2387212fc470af66ca65562e5e03f");
            result.Add("cs", "386d95dff649e69dfb52a1da51f2a41fccd3f27af023713a3d8b05823bbe99b2c6b7cf460d83dfb65ef5d9de1276ef0e8cb5d104908f049f717f70e314e965ca");
            result.Add("cy", "933cb23d2810dba5a0216140d16bea177b6b4e3e95846d55bc52c7f1c07b200ca0841605f7785e34765ea67388511dd76cfe1ef54a88da5d81e195a0e4220ca7");
            result.Add("da", "ab6c2f916058b75a6a817f3c26de69ba676af3937cd2c466a877ad475cc89fdf9c8c8e22c56fcd37c1e688302eaff9ee962fcde67ecb3e239377cb2463f13a0d");
            result.Add("de", "99e7882f0fc9c531373be71cb98ad036131fe8888eccc252dc3eefd828f6358f1de2c96b9c001cdf9f39d88e45bb8804d9ffcfd6ad6c2a93a8a5c03dee268f57");
            result.Add("dsb", "0a7e6e9677b2c540d6441555ffd06aa3d6b00ea7e9ec7cd9444180360a9f8a34f0df45a220136b73f7cd6c75b0e0d0404f88fd5ad8e6e90ff0f99b6b24405c70");
            result.Add("el", "6969dce82cb5253e73245f8828e7d0cf7c423d8838efed75c6d7724b11462d50de33350739060bba1801f7cb8a369d6a8b6a86d439c465964fee8ae53a7e829d");
            result.Add("en-GB", "65e13a892b2f899495b9f83975cd28347028eafbb5b8ae0758892bda3dc700c4eb2fcd8831317f502112004c499a5d97016d2594af042e7d4061ce41579f0267");
            result.Add("en-US", "d4b7b36e0613ace79a71b0c99bef74bb66d85641cb02b2f3d97764277f65a457f866f78c3ba95040666faff0f50f591ee28cfd2c492fb7c0c975d47cab5cdf44");
            result.Add("en-ZA", "32911bc833b17ff33f1c0e866a91dc2e1e998f6d937741015e823676bcd2d8185352668bdb24832130373589082c90078c214cfc6286c18cfc064ccbf7c1732a");
            result.Add("eo", "ea1451cab91a0d8e658b1662387e3014714937f9a510f56ffa50e38c6e02b39b577d438a6f1bebd0943f2311daff9ee087aa07c3b469389189052c907b4c5560");
            result.Add("es-AR", "de40043506a15c44340b0f77504444b792e59d87e37298474cd1a7156344462f8a62dfaa28b5c0f9e8418aa77fa0b74d90d95644a608c29e394cf1a740e46613");
            result.Add("es-CL", "9bdadf1ab15d9be07f0c91d09f76081c829f952052344c897c3c5ffe7d68db54f4ceac54f4e6afbd55e64e3f61c013df2481b92c4c885b3947b2f9dd3134ddc0");
            result.Add("es-ES", "4919a407ddc80addd169b26cd47d392eea9b97d744c806ad6afd9cf8e26844f5d1dfe310e36db487ac0c88838542b48353ed083ea859f0ed13fef69a5d983210");
            result.Add("es-MX", "b4f9caebbcc3204945392014c3802d9c646d0104fe65b56cdaccd4f4f97918ad9aa3da964e8be7e9f5a0aa1aff6d0d91b360748c41d6a198c436fe939c232c4a");
            result.Add("et", "af16adcc7dd5526d2ca98f919b43e15060402a8ec59f866d4dd8f3e754d090e528429abaa1c38c03732915edc55e4f3b133fc13a4e22d9d75e151ad12f1fd893");
            result.Add("eu", "872d3836cf39c50d64b66cfe16dfa146eaccecd95c66550950488c577cd9406a07222e1d365ff07ef3813c8c35ea6f2e655c39f9e02ea177d2f12b98d6ba75a2");
            result.Add("fa", "17cfb5c76c140fe9306cbab1243bf88172f79dfd4ec12637671174e41febd2149484c6b22f4894754173df7e6d4845dcef1fd4a91663a595c69a3dc68faae1f0");
            result.Add("ff", "023e5935ff9cbf9de99b2646111af5b997927ff5a233c4538405fedfcfff26f970299f9f45c6ed4b25e4566249d34f7105171d3a7be30755282fb29c627f69fc");
            result.Add("fi", "e30cc6e3c2729a043a0a1de1ea57fc4e6d11d40c200d0dbe6dcdfef9fad4d11eed073fdd2e978e0e0c26104d86567a5e95f12f71d49e908a550571f8d9f2d1cb");
            result.Add("fr", "210ac344f0f55752a7d4d33322afe969a03837ff27cd1f4f22cb777822c698c0beaf92c03bf7f7b9c9576d496b7b1dd1169c54f6f5ccbc5e5f3ff4b4680e50f3");
            result.Add("fy-NL", "0242bdaf79ff59a0c414740843f47c046ec0f176b291fe6de7b6ecbbe8b13712a9bd8fa055409889c9a17d9d0763723b6aebce4a38c940a31648c2ba6369dd84");
            result.Add("ga-IE", "62e6d8d8c211a4f5ece4ee77599b754b117ee9d44510cf5798b0d909f579d73b253a0d6103c65720648cdfc0886c2116db70a829793ebc1e1c85b9f16c588475");
            result.Add("gd", "5265d8d0f0a2f71817810e4c3a263fc7d426904c50f63a92fad737bf2931a18a06312593c8454cc7b82462c37053f21414862cee86717e5dac7d00e5936818fc");
            result.Add("gl", "4502ce5dbf73bb1c207085b151ddaccafa0f1546f8b40b28a418a1ec4d6d782d7ca358fd067033d27fdeb83e3870f934183b15af5ba8e091ff7533cf2f34320f");
            result.Add("gn", "110958e49b4239c4721117583aab3524f5c71eaf8ad012ed1ed8e39b26a308a9937a6a1fe2e65047f80829792901d4a61a541cda167dc7f3bae8f0ba7676087a");
            result.Add("gu-IN", "77a39bfb66a38e062c82a4fe7622ccf09c0ca3e169b6d1e7202e6b3b7a81e4e1fd1c94df27ba6c2c3067fabbaf8dd178f9a297538dcfdb0223bb511f10608a0d");
            result.Add("he", "447ccb0d550b44112d6fcc5d4282dac51f8a2532e59ada1fc5411212814115847a8d40774af487f711a64db514510c4be6158f18099aff485ff3e7bc6d555220");
            result.Add("hi-IN", "7099b28771f8ae5515c98bab4293bc0d513a35663a1074d3ffc25ddee169532207a7e7a48843bf9aa32ef4c705a3decd5411b6a2fb04acda1070c778c678e0b5");
            result.Add("hr", "b1e80024e20bbf1f2b04a00da881007f2039a656164acbece4dfe4fd4d74762e820e94dd3542589da5f590f09abacd7ba0407f47256af486c305b76b8e6f98c3");
            result.Add("hsb", "749b73cde7ff8244f6724cb49930b3f2791d42e3939ad7271f0da9d60ccc4d4469c7d290ee70dad8d059f3afd6d3c5c21db2bf01f72c27019d4c6b713c450202");
            result.Add("hu", "e6d462f83fa5eb1f3f1f48ced5dd69b8596d39f241170d67615c2672e3a64b3960d060fd65c5d5d27f0a1c46b522767666a7c354a1fa8e2472aaf69ce7045a73");
            result.Add("hy-AM", "0ac15c592a11bb68602e0fb62a8283f22875e90eced81e309dd5caeb5f04407f792d61692d142230b9e60a747db1a46f61888448722d8b7ff219576a56256c09");
            result.Add("id", "223def2a8f9269a9b2a91f800410248c21d7590e832aee85a577056585798cd22f21d02f131a3562557ef3e32d9b9713848c01ddee523d362caa45e46989c78b");
            result.Add("is", "952bbd1cdc4368dffe67ad4365209339913b96ce53cfe810f52af56042040d81bca8eff6f9d807cbe5c749f5b8e1ce175f431bc0f2c2205a592119fcc4bcabe0");
            result.Add("it", "ac1ffdd903ffe1a8860944b0601b00a660d203a08a5ae081440a2add2869fa06f694ddd8b22bb9570ae3c721b58f0805e231bd5a9a32ea0b02b8434576e43027");
            result.Add("ja", "31977b0f33a29f36eb4cd1dd156060607bdea745fd18e10d1c32a0abc06c27aa83fbb08d816e9b8c2ac1d3599bc28921cc071743288f5ca91b9bda3c7cf37045");
            result.Add("ka", "50b7b13dd3d0c2015dd819a55a59960ce6d975295c030704d0ea4010ed2dbf0de23bc305e61a4a8ab0ba9bb78c316de0716ea8597d398d4670b0627f0f1a25e9");
            result.Add("kab", "da30d1bfb30700241c3df9cd4d1102a4f6761bfc58cda40ec71c399c97547ebdf2855c501d2ba7e609117626d988d7bd38268ad0bbe54a8fc167d88db769870d");
            result.Add("kk", "d0b6063b4a78df3712bdbeafde62b6f73ab88d418310f8dc038e6e9eae9a79371e00bd9061d9b9bd5723d6ffb46439da162ff3d82879f45d511aa123b055c972");
            result.Add("km", "d7b8f3064d619d44e75332746cc463205bd793625ebb277c0df8c4606ba13951bd7db5c0ee9eb7aff30e0399522f7f67ac204b6336da98dc289609260167c51b");
            result.Add("kn", "81cb5bbbdfc15d4e6d8425bc9ea1b10ad916b3c1fc953bdd06eacc4c21ee9e1a116b3c4908adb30877a236d92d4c39eeebcf769f0f4c7e2cf86baa6dd3e0e15a");
            result.Add("ko", "629952bad2e0c1ba24f48dd66a4c149027bfe262d6ccf0ae4b9e1c23966cd73df2ba2b309e52b8faa78d350799d7cfbb2a7999f4418373c124d7c8b954e6b67a");
            result.Add("lij", "ae24d943c277ced212ca40877de86c58bce7a4a72c47113211617f0dea153cccccc4f14cfde9753cf2667d79758a39ed815e5950e31dedeaaf8d5d8b2cd70c3e");
            result.Add("lt", "9bf26a47ec2899e9b55dfde792451433fb342bed34a4568520aee1865a0221ba0ac532a6fe5e843f0cac8275631f9ac478e8da78d6de464f89d8ef69cdaecb1c");
            result.Add("lv", "5b02556e1dd6dec8f5fdf34c713242d39fb1798246d0eba9e0b051c6c89562edb117cf0970592b46608030c9c87bef9b9f6a52d61358bb56b88c72ca2c067a66");
            result.Add("mai", "48c041a1cc80c10a5113b18296c728ec5cce548cef0d8bfc247e8f802891a9f59483650478ded7a0ceee5337e4f395c536504a6eba832753a70efd47076e2779");
            result.Add("mk", "d4951ba8fc7f7525d1d51f3e4404ed4632f42fbd2f91e03c711f54db1167b44950efe7be6c7b771c66ce24ea670d975e99a853da0c6befe3c62eabdca6c11992");
            result.Add("ml", "2b8e9303331892346e10c00258f27b9502df3e9341ce3b1b98dd545923cfbe05ba1def90bca144c250df448e9f57a1bdf9d9ae12561de8552e15ab95b1d0fa8a");
            result.Add("mr", "8cd5bf67d6b254854b7214b28fd9022efc4aea542fe6f335cd636735ed99ec3812b03fe4ecba313ade51183d4aee4e1796fd839891eb26a56fbe9bc322c4d826");
            result.Add("ms", "31b3c07e7810b005d031b6dea81b7b85ad5bb2660a49040db732594033ec204efc637092d67ebbb414c96bf31ef9fe59d45413fbe506ee0d2533cc38b0809250");
            result.Add("my", "ac26fa4270c828e1de0636216981baa2e27886ce3d02862fda7920cb9f6564b04f0e53596e39205211c4f5ce4addb7d83ddfa0d4cea3cd9bd9424d8b7b9bd75b");
            result.Add("nb-NO", "9a4c2b6ebac66e3fbca7e06bc73acad52523cf2f64de7273d36f28469461e74f57d35c46566f969120f56d290ae386b51463ccc65ce77d34e59bee6e04fa4323");
            result.Add("nl", "f7c792e985771326c43f01ebf7701d4d3f1bef5bd9be5c537e3be1cd0757608df707cf2ddcddec60af8b095ac650c88e96eb73b58fe0a48df408b60f8572a66c");
            result.Add("nn-NO", "6ad7d811ef54fabe6571b882f4c02b8d0bb75cea8c65cb72a5f7054cf46de63b22f8ddf4a4723b99e47c18b144394af26081f35fdca1f55c5c2a7bd79afabd34");
            result.Add("or", "32188639457023de885584d98d97d96f2ff318ba4091478160e2187a1aec20de6380afcf3afc3cb0b5db5d1c3b455fbb93c7dc39999b0d2b7bb28160ca370054");
            result.Add("pa-IN", "b755d72773f2374c4ca09195cc7fe7bc8708771f8a01a3fe36038fe9f4f0ab4c586dca616af36e33fd19d160118691ad13a2112cedf2c59ec13962acf77e8aac");
            result.Add("pl", "1a81447b6ab532d05d8e9d082e3f339cd06288b75b35dda2da7e6211e11a894b9cde4d3960a73a76d6f5166be629e67b1e8daf089b4a441ee095d782b32c7cd4");
            result.Add("pt-BR", "c08b532ab7da14d945d2b085ec7645a9812bf91c6edaea15ea2ef82963228293688329cc1f0ac9c58c0f86c1fd9f233ce275631676eb41f530d47edee7c82ccf");
            result.Add("pt-PT", "7261bc2361d86c3364d5fa10ac2514777b363727af9a091c3517f607aa4a8b0e8837b961845c1f0795e04cf292777d935f88aa300937259769b435851b39911e");
            result.Add("rm", "4ece9cb1d7857869ec5a239a0b2c2ea61f99725a229e78deb9881bef6d1c905f8c2c1ecec4ea2a6ec3f3fe914cf858c9a761093ab36170b17c7564903e3fcc8a");
            result.Add("ro", "51ea06dd80eb191d885fc741ebe7b754be697c5ff5a0dd11297d194411307c174ee08995fde1209f17c50e15187ca215266d973656abedd8aeadda7a25e37834");
            result.Add("ru", "4b5c8098b2efbe1adbcc629152889ccfe3d414396e1f999e8efdaafea56316c28f5dc43c6739322a2eeeca12fb2de328e9edf6cb18d08ad244b770d750f7f4b1");
            result.Add("si", "12533a14c3f643a0386ac8619204d19b916c16740e337d6ac6828635ee3a2455c7fd631769cbac7276a4245766e815447831a7bfae43e22e9b040013a59e76bf");
            result.Add("sk", "d47196dcee730a35d4a507c61e0ab9388890fe5fe03d8974a1f6e2eef6bc6f1295a05009a1c0b6442cac5d14f283ab36601e25ec06686b84bf85d972d8078c66");
            result.Add("sl", "249a19bd661ddd067c317f9185d6f1ff3362388a0e6a92b70ece4a41e7f897a5d4f98f11b9b55592901114b6461df9af188827bf9e454c752d11d69826a12d37");
            result.Add("son", "4be17bad2a80234076bedb9316f4fa8e3e6ecf9dbda2e5e4a2078113a3eecf788e96f06a07bd8ccb36baae5cb4a15400819b676392251c8cf95f138b476116cc");
            result.Add("sq", "070fb145ca46861d76d32e28f7b6682e027659eaa0d74e425ad768baa93d1ae078f498045842c5c3da70c3596229d0b4b30612d8b16ef03a4ee7f7792b474962");
            result.Add("sr", "c966ec53a56d27cad65334d65fd48f3b9c23b9a59c08d858843e55fa0523d500705b191516348b1fa0aa0b2d87ef4d216ff4820559401b5668a33c4c6dfa6e1f");
            result.Add("sv-SE", "26c88d8e47ba27bad0e1f0f8d1e8951a0082118f14264481481cc02325e8ea98d5bcf507f429ddd3a4e781fadd1882d674e76580a275c9c192a3f9fa1ca348e7");
            result.Add("ta", "a760b0f0213b0e55c0c0cff175de85108a2e767326149d13d6a24ada5910e21d5d16b3c6254a50a1912a4f0031334f03e8eea539add87e380e7e094b22686f20");
            result.Add("te", "6afaecd3b59c82418a27249207c6a30b0f49e647cd59910e80024add5c369eaa61bf2a510cfcecc77765caf920d58b4c653450d9d5a170bff97295bfc3da965b");
            result.Add("th", "914017a354cdda516ea21ae0defdc1a276d94e4db8def91e7ab51b988417091bb0bede25cd5eb9bdddebe9cfeed6d7e8a3a11f5aa907f9426b8dea444ea0f82e");
            result.Add("tr", "6982c40e549fe6f085bb88056a45906fca59474e7c1a2423413e9c940516fa2809747e23e13600420526ddd799a5b929606cfa4e5b5b5409b5528f6bc97e5107");
            result.Add("uk", "110812417633f327acfa7ef320cd9dba62dfcc310f746146ac3df6fb0d1c1bd19a1670f93219f672011c8b852cbfc0418d7506a7ba8152a432a0b3a7cd2c63f5");
            result.Add("ur", "6f140f9262eefe2b64c4d4e609fd75f7cb21ab3359aae48b1685f4dcc193eee4dc43369b8b49df3f1a29184d4660d7b3ef3499bf1fcc482bedc2c03db8e3ed90");
            result.Add("uz", "0fef308a7002acdd18c013b69c69631c471e9adc5831dc61280f660cd593d9a2d6250246d6b32a7f1ec17c29f3d33e4e240ce15713dc05e34f555da50ff4a265");
            result.Add("vi", "b9043bbbde20a7d39655a55df31acd6e56c279645d7425d1daf9a41998cf9addb1021458b9610db06f6a2f853fbf205a483f433321c652435e0a24529d8011d0");
            result.Add("xh", "e3fe14feacdf3896bc581b39fdb3bcece33ab5bfc37a3bd02d3b1ef30de784b1b744273fa0cdf9ece7f9868c7a0d4f32f5e7b68163a88697a4ce56772b1a03be");
            result.Add("zh-CN", "bfa335416ba96475c65afa95df21a8d6ee49fd530def2042a22b824294e988edac84a3f2b63c58e954f3e94cc8b33e9bde61c00442a1d87beb81f418a2bc04d0");
            result.Add("zh-TW", "289529bfe5aae81ee985fba3a574e47f6dbe431c0f98b8631a91038f40ec42b47bc9bcd311daabcc47142eb5f0bb466983140a84529d532629c47412ef3ce5c0");

            return result;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "54.0";
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox")
                    );
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of Firefox
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// tries to get the checksums of the newer version
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Debug("Searcing for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            //If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
                return null;
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } //class
} //namespace
