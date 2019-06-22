/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019  Dirk Stolle

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
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Release Engineering, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/60.7.2esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "dd8269104f7f5c6a9afdfee9ad384850ae16c6606d47a25f5e06140208602fc3a09117d2010d8b937dc7095d7f6ae0d7179c14596b86c6cf81b3f60a2e807fa9");
            result.Add("af", "c2a2908dd4a0be534d6cc32679e48ceabfbffaaacdecb83d535d14efc7468b04a1b63a9b64b8c33c0b7ac16a90334a046541774962ea3686ca5a8b891748a9a0");
            result.Add("an", "7d6cffa7b86fedafab99793f1d9f08c0bdbba9c0bc527a4f6ec9b0bd899a57c202122659a8a0612c5b4973ce34755f4015716e3080faba7111db64b8e4f57047");
            result.Add("ar", "117c76e0cc0234cb659004a0cff7a5701d7a204a6696ad772e85e15acbbdb2d2e90e67afea0b34fbcac182476b7827c8da123215820c9a70002060f0ce66c229");
            result.Add("as", "c99db75ce35cb5a47a18a7a53df6d72b975175c76b1c26968b9cc1f23a56a676c03d0891f60b835d3580c91c61ecbbc9bbfc0515c3b05d3c71feade98ebb7570");
            result.Add("ast", "703f0a96e9c57a3720d6389894ad58ce052276d02509bda372c5db7b8951b632b774884e740b65a2e14732ae0895c16ea24fd4b313ccca1e4838a9fc7f6c037d");
            result.Add("az", "bcca83b65fa997ec8ef4b904dcca1e1b9c1db452e9b342239fcf6ae41cad6f155992ec14a2595b2d837dfd2941f2173777602cc346e33ac10f7a69527f5aead7");
            result.Add("be", "0cff16513526bbfa0d05fd36f0cf0121eb6ca9639e0b700a95b7ea3a7e69b0c20ab2abdc574d6c3dfea11e6c50187253deab67fcff1596649d94801322475413");
            result.Add("bg", "6ea0c7a43d9495657b97f91d81ff6144c71368a0483a8f1a4cc03ce8728f105bd0ab53ed191c26e1dc5103c4cbcad9ed86e7ff395393ccfead3ed7b0288ba4d0");
            result.Add("bn-BD", "f2dce74d9739009fa6e3e37311765327f32c6538236b662b590a8f220d00f9b709355a5b9162c926ff5f5c09c9890a5e98fc8bdd9201f65921191e5f72424125");
            result.Add("bn-IN", "3019c759301d8ed4e483bcfffc7f4048e0eac08b027000b68c256ca1f5a4127e3cd3084e3045a78acbc989209fd026eb5073cee9b3f3db4e631606f8c165b8c8");
            result.Add("br", "e44ff5022c54aa5f1d856fdcbdee03167450bf476465ed690f1d3e67ae1709bedde09885bd4651fce7d10fd94f1e8e0df67dc7cf066130ea9bd9613838d361fe");
            result.Add("bs", "1dbc2e10800855638034568d61fb8249cf85ae1e4eb1a5d686c08419b20cec2502d8d0fb78c0d5ffde0dce0d527c29c2bf9b23b2d8f766ab18befc724a12a698");
            result.Add("ca", "7b4aafd15f583e270989df61756b6eedebd6bd0e745dee6461a8006026ea81644f02698f025a585d9edac090ccec9351b53d3d528de062e778156c07a13709f3");
            result.Add("cak", "6a2f36ab871b6e290b9980a4494783cbbc832d12194ce2df2a65e03981fb5ae62d0dee681bb64fdd123b2442cb73163890b2f3f1e5d70b5b885268d9e9380755");
            result.Add("cs", "4e00e7c014aace34be7c5fded4d08a4065d7cd3b97d117d2e99b2fadc28c86fde5cb1276af4e911d66888ff2cd8c0af1f7c1975f6e6c1c788e01657845980f72");
            result.Add("cy", "390296cf1ea9025966f88d6f748901a64bcb213e3c795c53a49789901e1f80974bc9ae7d5eab1399e1e738da4b1e793a5b90528c917cfd60d0345912ec1aba77");
            result.Add("da", "efa9acc665d67d9657b232965e1da5e7eea4b5ebd88ab8b7182ed606450d5a99c65fed101e940a562fbe166c4c00fa21b0989435de92bded86aeeb6b5cba7f2b");
            result.Add("de", "3a93f7d7dc6eb93a891f26600f4232782fe16f2f15ddf5fbf1d923f601ca9e54d4af06c551821ad329e4fa1aea399f97af7d5bd64537410e62b8ecfdbd8908da");
            result.Add("dsb", "bc8c33862af9b195ef2afd83fa0b0214bb56651264c551b25f31a7218f0de7ceea74683501948bad8990a1c714c38da3d2eeff3eb1a705b94a3388314b88d43b");
            result.Add("el", "2774256ca919b4e69a27b1cbdadb6687e2e3464e3d0669c7a5acaea9b74aff42f928e8de102a8c1185bf02b8cb9f75ceae1ec476f0be8813529f8ad5fdfb3468");
            result.Add("en-GB", "fe2fa3691d71fd71746d33ec267a7ff04924e051bc63f267d11d272eaac2098218926162fd316a3bc99eecc0ce70a7e875ae541f58a29b74ea82dfc38ea1bf46");
            result.Add("en-US", "d1a6768e8a73ce736befa4e12292e719431cc7f3fa723ee9565655fae3194890145f1501f32eadecebd57837f14df3ce65ddea37a28547c4e659696b29cc5605");
            result.Add("en-ZA", "a4080cc786127d958c03647ce326c181589ed87fec5ee040073b394060c618d94c80cb5ce57e33cdfcca1cf54c4eb8defd17a385dc3da90832c77fece7cd0b8d");
            result.Add("eo", "16956b5a0fd879749b9caa3ebc32a1d39adfcc1cf85490620419c833a7465dc7eb1e8d077d3c85a11d114af7374d496b2c63ebe621584621df27a38f79b075ad");
            result.Add("es-AR", "c3289eb518c82cd00123b1191fea6efa7a5cf5e4fe037c770585435ddf75baf9ee41327d845bb12e6c53bc77584752a2fcad2573f48a99142d630c330f89c32b");
            result.Add("es-CL", "50689d0f9466a12ac4986c126fec66fd174aa5e870c24e54497b30775a6271abd341d39dd20656071d5bbf5e5c63d56a7bc7369d23e4af29b5cd2517e09f7c7f");
            result.Add("es-ES", "8bae3001dc2ebcbc13a98c96c26fedebb2c349f2dde8b962da21c4de79bfbfa01d33a0bacfbf9670385fd4d97a1ee23af626ccdbad90c7afa3a521c79ee8ac3b");
            result.Add("es-MX", "54197a361f820b7a7556751d8a2733f9e7141d0275f88311165cf7db949962a8893d6b3ba87e98b9548faa9e919d0be6a160962bbd7dc83a97073510dd950e28");
            result.Add("et", "7b156758611672728bdfa18cb164ce436a47b7d910ccd85e9f48ebad756a042a4b7d7fcc120d9fc6a9b7106ecfaf1ca4df1d4b91c3462cf9305e3774d19b24f9");
            result.Add("eu", "d23672a4836f027801bd967145c3cff3efcaef286e58de6f120547ffaad643d626cb6d21a0928108a41513b982217d5b62e45ad959bf7cc49dc6e581ab42904b");
            result.Add("fa", "9b1f6b7337759bdf00472cb69c8c2c70c35581c59b2de1d8d5c78a5f5d16b7eb7b0d68e6a6a6ff1f0d247a02ed4d2c77e90fd5b485df28b2a59c9e2475abda63");
            result.Add("ff", "0b0ef338fd33921de0c71e3fa8045208abb038c821f1e24f79e07aa7c6741ab173e69ffc3d1c3eb9710227d9e9f09e26ae594bec2155fe506dc46327062511c2");
            result.Add("fi", "6c79ce656acb7f4cde1ecc41f677ea4c9aa806665258c4fff1f55a02d615e0606ad290c1bfc1cff3b9b178a03d2c20caf87cdecab0830276d65967229051d1ff");
            result.Add("fr", "eb6922a41a4a4e055bd83e71f5005cf6dd32f20cacfeecd0e0b22e39588c3b47111f36295d01d13986ab7a6bec92f8b17940385a1cde26b54c9dc466913780d0");
            result.Add("fy-NL", "90ad887dc7147dcecf217114301e1d61d7f66f2d54c234c99c838676dfdb3df75025c62434b6bf5f6e9ae839e41b877aabd397989b949e3e651ca54774b55991");
            result.Add("ga-IE", "eb55253b659b49e95aaede6e1aa912a62a841bcbba79a3b01f0b54fc2df71cac1d348b8be9101ddd74731daaa1034bf03fa33684b09c93a02039169429121ba4");
            result.Add("gd", "4f89f79368c3f5537f82dab8c97f0902aaf3cbeb0a8371cc9f9cec074ea20738f4d995c47b3007a8497b9ad23918f57352e0abb1b897fed4ee614161ad399f5e");
            result.Add("gl", "bcfb532e4b33fd06b733f95add907e001ef7eeeb36c2504d10cd65c6cfa0128131fa05c593767f3b1f8cf52fee7fd547d793338b825896b29a833b1e71d8fe0c");
            result.Add("gn", "75d20184be544cc75d45c9258709ad6050183f7088109c96a253df8e68bcbbe6493d76fddbca3deba9cf9787c22a40e2b86b1d0096d0e3201088d934caf88437");
            result.Add("gu-IN", "43f10a1dc3ccc08df517605bfd148dfc43728cd7d652ee3d2fe171b3699c60f1ba9cc883a2b69de11b85fb377176dc4d41e2d23fe6b713de5c86511c9404a5d5");
            result.Add("he", "6136fd4b85be46b24208c0cc8ba767edf441892cd49951765f0cea3b842b89d4dd7246c616b98ab9a614f0ae5ef9d2e16305d04670394b23255f947868d52f61");
            result.Add("hi-IN", "bc43fc247de1fd5268226ed18e490830ba9dad4f82b3c97dda0f244188445b767cb09539ffa665803eca95ecc1fab9980f8d23a6bee34ea1104ce4b64aca4262");
            result.Add("hr", "d2431a97357f8eb976b96b1af1fe0a43cb5a081e19af32381c135b546dc15af3394dc95ea3ed052804a037d8088c6cf9aaeb807854168e4b49b19a2ecb977e31");
            result.Add("hsb", "1e86cf422fa884f500b33a6cb1f3e269ed88738a520c1838ffd97bfe8ecf95e2cf2cc0f114b6f137a6edfc01547b5ebc81ae56c813c5d54a0a161dd0eed6ab73");
            result.Add("hu", "35368e374ac4be9ac6c96248e3eb129be69a817ec031830a83ede563aa3e5d64c151899526563b140a261947270a9d6cbb65a844104ff4607ae7a19ebdeadfae");
            result.Add("hy-AM", "f8034e30221c688fe798139266263da216d23f813883ce9b4ab4cfb89e0833aae19f7ca656f39ab080ada6928a0e8ddec945d223f8002c53163a9d8a245f4e05");
            result.Add("ia", "4ac6df52b1961bda68220f854aedaa182bb20999b386b5fcb927d3cca7619aabfc6ad3cf2e1a4e4a91e30ccfacf52e1c9ccd6a1f18fd848b1a18e407da25de43");
            result.Add("id", "b8aed76a25d9937897e37782e1af85071cde31d5205f495fa23e83ab1a81e1e47fc5225815bdeb2dcbd3261392a65eaadc89f56755cfa409fd436896ccafcf80");
            result.Add("is", "89c71ea258ed5af75936f94424784d719dd734c05f20f630a20cce8cdad010e15a44ee51e103b0fbf4cd6b90d4479272f24c8c43601b198b8bdd4a2dd5643055");
            result.Add("it", "43044c8530197c99ee22573328aecc6cddf98b2e16adc8dfcf3de89c3a4d76c7634e2ebead47ee8f33f256888729d9ebec112279298547d6135c7e5d58b711a1");
            result.Add("ja", "4555c541341d372b5cc29e504d97efb60947c82a3148d32a947d3006256ce94cc4d5244668c22931a2afd29eda0acbf64d70e33851525e0f2158641bddc9ed29");
            result.Add("ka", "d103d93038d72e5b67dc827b2bfe16d3be0bd1ab53a742ed11737b4806971807aa62893e715edf22fe91d574af317fd01979fc177bff39860fb7a4059e5871cb");
            result.Add("kab", "705dffc0a6b963bce7218996f32782d676eb525c9c81a9528867d85ca4535f4ff779cfd6b5f1c6b1595238835d186f667386c7c17f6f583d33abc3cc48346a7a");
            result.Add("kk", "50e42979537a31421928197f88e531dc5ab12aff7872d180cfb44731a49fc7c62d29b3605c330003d4c1de7524c6bce887145f80a0fc80e052b8ec266cc71f19");
            result.Add("km", "ab8de1144b30f902f8436df84e130b075e131440f926f604dbf6b67d5eb9f53023287d1495c9f5708d8ea9625d60ff22c9f6a8e7266bb0c4920f0e99233a6add");
            result.Add("kn", "40eb26982f90ce0c93ac6a283fb4c8f1fda637817b128d0f99c48ff0e18239ee6be354af60d42a9d7bf1c49f852bc858cde534bf5754a1768642e40fe85a4fdc");
            result.Add("ko", "5daa3d68ed5b4af6a9be471f1b9657efb2afaf5a4e8225d1bda7be66139124932b88f1ab3966025d28f9e07f6dfe3fc8b12c0047549b5bd9984828589f6671a5");
            result.Add("lij", "621d80f5a090c59eb5e8ada507640bb361c96f71fbad230435f47a99cee84f8112a56ab862fd98e674f8f68bd2eae9957f8f3f8be0147c88b4a0324ab3f6651a");
            result.Add("lt", "5ce8579f1674440614f6f622971f317df9f655698b66d8551ce778b74416f121051fcdbae73b8a4b5dc8e1682f3e43397828c48801a997207aa2b768884f7a8e");
            result.Add("lv", "b73de1af4d8b35c77a5f1951f2112b6413dd4568a6a59e5f18bdf36caccac2ae17e23443196f648ca9b8475d36d889b554cf59877b9a18154afecdf4eb96b2e6");
            result.Add("mai", "6d7892a43a89b4022900fd9c908c9e6e71597f71fd2585cd521c00bfbf8d54f3db842cdf3249178b68e62f7f6b288c2f1ffde3e4e502fbbd74259c5ef527f349");
            result.Add("mk", "26873e138772b4427890969bfdcbda2e8b7114750ca46e6f0b258a12ad3424031cb614e5d88999229ceec1fe0b6a5c4a2f47b79b6a67818c5f8756ddf196c690");
            result.Add("ml", "c826c72769972ed95f7b5e45bbce0c064fd77ce878fde0b9d7cd2f603dd1843efe059bc613d414b7ca9cae465b1eed6efdef104aca829d34cc444641d0dd664c");
            result.Add("mr", "f00f885f7157fcab3f0525310a5dbba04ef9e6fdc0aec26c3fefe382d2981aced37e26334c5743ac644529c9548ef05e8a5b69a8a485ec2113f1223dbdfa692d");
            result.Add("ms", "8690c5d84bda9b80cef644c9f37c15330016d2f1773940735ed62f1744f2610d73d47d506414b06236ebb61317ba467553e696735caf61b358cf46ce1cf59391");
            result.Add("my", "8a257d35732fb27fad31b4bbd9e3a90464c6e00fcf32530128fb1ad050a8d62ebe8e884dc95e14ab5cc2630722278b12c4444e4ca2e0bb5e20e80b5a36d85435");
            result.Add("nb-NO", "a42f5e00717ef73f9af5c5354eb9973b66a80621c546850614c0469a4d2866a5034dd58885e00f06b2f3d4518f6d65d546da7d3789221534ef7e8b4179d17f55");
            result.Add("ne-NP", "ed40aeda808fe83b4a73217ddd943de5f48872a168468077d3972e1faabb83f6bbfa48e021c5f6e17344181107a07400681a5120f563dbc54228c311af23b67b");
            result.Add("nl", "fa7d154ce7c3e47d9a6613f7aab2ae0bc7b45817eb0860178606f17f75de10184c00ba7ab9cd1e3d8fb3d49d93ffc8ad7eb98a89b6ad38ae6a224e7ff26e7aeb");
            result.Add("nn-NO", "ea2c2ee3266697cbbac5473e1f1ecb2833de177b5c864c20dfce604f8b02548dc52118edf9ab8bfc2d0d3cd8a502f440ecc842ae0510caea488cd6beeec8676f");
            result.Add("oc", "9d0626c38b16bc79acd15210f21c2a8ea66ba44285258877ae1a1f5c0c6b7f36392a669d8c8eea4a88f185203e8435b7be8c45bbaf024ce84dc96aeee0e7297c");
            result.Add("or", "0fc6597ca028aa67841e1698d33eacdb827d540425afd55ca83a131c9e8915a9e375a3afdc7a2ceb61e11e5bd4227ea58fae8ddde4bd9e66404394759d3607a3");
            result.Add("pa-IN", "f1e59c3a9ce41ca26b7062ba085736d02cf0b276b77fb67714d0f133ccb933789a3f6e471e7a819fdf7aa98312e90762e2be13d20ebd79b8507936601f7fb883");
            result.Add("pl", "4076e8487bd44a818fcd404c83470cecb50d26c6e1284026cc692159b58408d053fc7c69222cb80f38d8889a74343cf53b1002cf9014a7f385031d6b8c711b45");
            result.Add("pt-BR", "c3b00607d805c60d48e654068ef7acbc9a44ab83780f0cc530aa3bc41670c3657afa674b17b6e52c416cfc8614b8adf7c288a0d55131fa1b716ad2a47f897721");
            result.Add("pt-PT", "0372b7a33bcbd0325759ef70fa55795928472a62335d6cd4276d1286e5505e775cd2bcc4c787c95c34c57deccc2a2e83834d4517bacc716997c00b549b34a707");
            result.Add("rm", "8a7a0b5f59eca9143be40b913971e85bf358174e3208cc3e573ad636b809bda64f59a42e3c54e5424a14529864364c9647b148bef47451c99fe0a627a64159c1");
            result.Add("ro", "ddb734d61d89f13fd11be51bdcbe7d315663f192db0e0d945503d109ece913d5341fbefce84f84b13a689539160509f9d5255f5b6a3a3e8b0dc9208ef294bad8");
            result.Add("ru", "e41af2af9160eb3c3dfccdf9d703e873fd0a657e815336311347a5b802b162a1f19e7ebb535e287ad6e807097e07b34b7491ecfdb822ba0a2f772d6096bae536");
            result.Add("si", "b8ae8051c6ef27f32f3af20990b2dc88d8d651b055bf0555660659a563f7927da407e41754ccd5dde6d6f794142a1163402152cdc9738a1e7dea6da0e8fa38dc");
            result.Add("sk", "b5ce5a4237427b72bbd09d444f0115920e572ff8c809c7e53e56fed18662c8b9e50f39bd2b2c31f18c04b22b14ad2725f5915fd72badb50130ee55cf55335170");
            result.Add("sl", "c07837f2da7ebd9373e0186ce633eed28451ecfadee31e579910053fb81a05482d438aaf6984acf3445983316fb8fe6ed8f42848e86ddc866aa8b8169515155c");
            result.Add("son", "f0b1c040d3de204c5a206fa3edb5f8cf70eb75aa93630a82a8e1d82d524ad65f3e383fa171994c76da84ff6f04f946b750a90a23603d6e988c659be1010aa419");
            result.Add("sq", "3bfd1c1f6f016389d80e28fd8ad9e58676d53a77bcf73d45344d9e179e6b1105a85210ac6313122cf9d6152cc9853c816c8d879dea380b538dab7d69458adc15");
            result.Add("sr", "9b5a91000b7c0e9039b666f658a0146fece211fc35f170793f195a9a44d915e930f8d8685a9f08a8c492a3acb86181a4572c39283cbe3f29de9158c4e4b91776");
            result.Add("sv-SE", "23fc96c20e1e0ae6ed62e5f63579a03d5810e517eeeb83a0dab240720171a9fd8b51ce7efe5eff1c8483f5ef8e3b0f08b4ca06f0f453e595795026d6214da486");
            result.Add("ta", "e98ff89568776587817644a8c42b23eec7187661fe6f7bdc8d5129ac5177231a621c9f814d3b5b0436714b6328f423233ea965c260ea6caf9d52fad171969ab1");
            result.Add("te", "b34e2576a2968e6135872a870b26f251fa62cd8dbcdfd8fcefa37e5ef58a1b887e4ca813accbfdbe7b4acc46d4d0bf1cb9d4202583a573680c2ae17ee655c837");
            result.Add("th", "3427b554b25d4b4fadaf22cfb2f210f3ace1446d79f8152b64e5fc198256cbf163599a6ee225f2a33621918221b2fe7020dc18210a6bfb58063c742f1852be35");
            result.Add("tr", "9cdcb9d622aef8b052945ac2401b0383bc383481d89cdd2e46dd93b66c265ef512bcbc8a36d4f2d21079cbf771fd77b762b3aedf074d8c6577b528c6f22cf7ae");
            result.Add("uk", "fdba4c1a1925bee8f916de5c1950c0f3f0121acd1c87e146962edba241423e4c15464702d5dfea7cf91a455d154a0a8c4e06a73a8eaef8a69e9894109585c52f");
            result.Add("ur", "974317240e47a1a8222bf66a51be0e0c12f2cea70f28a6927ff69962de9bfbdb45f1e625932ac98bf35bb2c1a35b12c7d7cc367fcb3b5b175f057dbeebb8fdd6");
            result.Add("uz", "1baa3b00ad0091f02639a666017d0717185f4be428ed005557a8fa4b9da304824879194850f9bba17718c87f58a777881e2cc5db300717a109173a7546d9378d");
            result.Add("vi", "499e56bffee189e7666c33613bcc226ca1c00f19ba4eb86a3fbdc09fdc37ec76b87b39983acd15238629701d6e200a8abeabd456559ea5ed5e283897ab48320a");
            result.Add("xh", "f09b3bb9b87cc196eb11404c15556f26e1bfe5bf1d0e55987afc42e8f566480fd35be8ba7e6a6c8b6d19526cb123203cbcfc087a917b122822f8d7ac23add133");
            result.Add("zh-CN", "68e12f6b366d265f7302e677120597a9cbf49d1b6fde035682625c2b684f8a5b533174e7e48242a27c09866e719991d90f8233e0b5d7f16858457a6ac819a5f3");
            result.Add("zh-TW", "d5f93560a82d4d84ae12ba644844ccbe5600736fbf2e3574a44913aee8fceeb7823e8b593820bec2464fc7a28eadda75f4f6b1339d9354dc59968c4c9a3ded6b");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/60.7.2esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "58601553f41d379c066aeeb4861ba29bbc5da76a40307d8f25cb55deceb2d8501c0c7e7f09843f7e8f285c1f9157a650bb57e72b16d0e85016ebd92ea29ad1aa");
            result.Add("af", "6856d8ba95dcf1b4d37ecb6ce345ed8d0b734a69530d96405180b3c6c7be6d3f72ccb78441d529b2a5ea2f6e9a8eb9bfaef1d24ada6f10e77a19d8d3f60926a0");
            result.Add("an", "b9a13620f2a06d0e8eded4c97a2a0a02627436aca3eda6434dcae5f90739a2e104e484afe434df7f0ca7ef363e937a4f2ef8d3efc72d8e49357d9df3629ac0e5");
            result.Add("ar", "139a7173241fc4944925686d7d7d957da4abfd95fa42611ea276a2d896dd5d9472c16d27fe8b6c8eb890e288891b29128ece98b23fc96bb212b977bfcdf302e1");
            result.Add("as", "c29833b92d2367e29b0b7160d8d78e6ed1ae0545880bbab0bc1e7192e415233d1a247883d0741be6a08194a4bf6af7c864d3e2d9dd9636ea3117714c44837435");
            result.Add("ast", "c888ecdaa8530d4f2f65d2960d3374cd4aad0b02ebf4ab6492944727139bde8de2c2a15bba21e5ff705bdbc371ace722099ad4262cbc4a47cd050ed49de71848");
            result.Add("az", "55bab8cb3ed6f5f8c3d349e72fd13af2e35e3dc7de6f454b063edb5c27b62457aa6385903fb25b657c83b754a114ae98eb3ff66bd5fe8d0548620d1dcb6c2f00");
            result.Add("be", "5e3dbb1aa7065e37ed2e26ec0096a6e600b5624e24987d617e54dc206f6c4af7d3565fcde17d7818243d44e08adde7843b4b69b557b5197a727be4bbc8a9e5d5");
            result.Add("bg", "c7b7e20a32bc63a492b152be16cfac7bac3343d75c06f1c9b8c3d4a078cd207ca3a88ae35f7941dba3f9007c87ce6cad4d506aabbeaa99c9201ecaf9fa94ba4f");
            result.Add("bn-BD", "a0af7b15f55f91f0f2d5744d44dda224732bd5cd25dab5d768f68fb84834a50c4273eaa89dc5ec182fa264272c8fa19720de833448e035ac82a02d4523cdbec9");
            result.Add("bn-IN", "92896334dd9190efdae29b47634e3cf104191cde1d9e53c157b4f5cc5b3a5c42dbdd090a8176116f46113f35fbba46ed6bd22b1e997c09f1beafa9d317c2e31f");
            result.Add("br", "24b18bf35a3db5af9d69a1d8bc5eef71e7ed8d542e03e1fd1b355ef179b02cf559ebaa51493f4c168bf52500bc97b6c7fd4b0005d38b15530bc77a35491e1666");
            result.Add("bs", "93b5a9df7626ee7ddab22113ff6ee5af4d628870b858d1afe457bbf3171621a9ee216c6cfcf079cd242ef7a040abcfdb9cc8adf38db1af57c8caa00b45355d92");
            result.Add("ca", "0a32618b7cf2a4896168cb1d2cdde584e5e15e9a214165f88d067f28f174fd2b253a68dcbc376dc847ae46f010def02d9262beaa15f33bf8344ad889e9a4c260");
            result.Add("cak", "8eeb3fcad617a7335fa06744ba28818c46d3085a2ecac628b4010bb18f23233e2479a8916527e4f5eaedc58f06c77ce4336cb7479bc2c74212530203f4425e0e");
            result.Add("cs", "c599eb7813712f21913d67720a394cdf19aecf1ed3efa5914e4484e70e4c7183559f8c2da2ce14279a912c58f3178e5d26c63fcf0850980548bee350d7bc82ac");
            result.Add("cy", "282caee05462896e93738ccebb0817ae8af44512840de74a37989363eaf4e4766e09545e95da3af79f80cc25495426f4dfaa0ea81d86b8d10077bc9f08cc6a0b");
            result.Add("da", "dfbf8459f43bbf93f0759c27b0693378fafb5586afa6ae80ffb9a7120f3062f03a0b6422743a3f163641f2fa05351c339386d6c45fd0fdaf55b8c1e98a48fd53");
            result.Add("de", "e51394aa2ebb7515d2d20040a4e538dcbe06111cb97d13349328869d413cae12b3e27abcdee739595b1196249663ac2d771e3e590b3711a6007bc067434b74e9");
            result.Add("dsb", "ef8cb2ee65ac9536e68b6c13abc754353bb3766581904e1d175f5a97becf320d0ae3b0ff0c16929dd614536e467f31b317f4eb15a92202d78109639eda91c68c");
            result.Add("el", "7b089f0dbd276628847c1310b2b8f6637402ce55e76a273aef9582926e8d9584a39e565781e886ce5486e7e1b1b7672334583e13a37c3460b11c6ea7f15475db");
            result.Add("en-GB", "25aa48d166c8f0bf4b89174b8f88aafbc42e599040eb417c63878be059981883db27ae379282cccd9697562f0cdef492ff4320407e8113b4dcd6b9a98e1c9c9b");
            result.Add("en-US", "91509f14a388b011dbafcaf202aa78f8ad491de83e43ee04583daccbb3b6bb90f05bd747711be18b07869061cae9cda7ff54b2c7c28201287d03b48ef06dd2c7");
            result.Add("en-ZA", "526f5033b7454c8970ba317531e570362f8ef7f28222a55b567d89d874795f572787cff7261b96186def12d6346bafc9d9da205eefbbaf61b58e593d879abbc1");
            result.Add("eo", "800f8c5f67d341640e4149190029a99e117b99eb214c58a3f6d50d110a0f668cd6cd39082ac775e4299021e61b81aba8eeb3c822e0afd97403a65f452e46ac69");
            result.Add("es-AR", "690e1f0f4a4bf1bc5dd20c2fad1f2996b4b895b0fbf022f06aa8f653fc53ae85f38e43c3a0f992320783d200606c1d196d15c86910cf4e31910b3f5ac6527bd2");
            result.Add("es-CL", "5d21fb13ca1026af13d25ee344917001e476a86b2905d7056402b5183cf0eeb07351c7205ffdec5513601f6e2cb275967af4917ff3e97b2ad8c7fe871108cf64");
            result.Add("es-ES", "a2bdd8d8b4ba94d711f0ad32afaddcc136957358cd4dccb08ade6464e0ee00a68d1c8e5c08d480dd1735e5447d38de239c5bf69b98537307938151fa62f338ab");
            result.Add("es-MX", "c3ecf083ba913d8730db35a4e33b9e27397bf29e6a2f63097b758cec55cd2296ff6d694c3a4102b576edc96db357732d83648362d8a7b2ead102d1a1e420480b");
            result.Add("et", "11111f0bdb2dceea8ba2fa67b0a1597553e915f8ad3a8788ea758a4040b891fe1b260617b59e9f233ff561d0823c012565b1220620a27f79b5c80fd4caf0426b");
            result.Add("eu", "e19fefd265dc9ce2fcaad41d9cef7a4e666ba75e9090e36dc64c76ee67db96c574ced5ca751e0f5cd3ca2ccd91e82dcdc529c4cae785d74007302fbab32b377b");
            result.Add("fa", "6f0bb3b420ed1fbcb12a68fed122d98e897aca497484525ecf1dd6111800ca395713b76af1903c29547847cd27b161ceac2a513d1f9528921283c4040dce07bc");
            result.Add("ff", "651a3d0069cc5b3c37c6a47e98ebb35a7ad687adb0904fc3ffce521771a6a54ab13fb63b042a68f9b207ee9ca142fcece158d8cdfb63b419329ea4e5c1db4418");
            result.Add("fi", "229fd4c7660baedf9c6d4d088fb8450c4a03c2599c54fec897ca96fbc28d9c2146fdc5fabed0445c52db059c73550fd4b641b731fd9a0c7294636c43ea4cf1da");
            result.Add("fr", "f928bf1ff5f66b9ae8cc1ea8f6306c15068ae6fb5f0a4811315ccf4bf5c5f846b85f6354c95f739ba712be33eafe11afbb1aeada04a3fb2c55cbfd0b5586c6c4");
            result.Add("fy-NL", "922ec4f2815e936d2bc3fe64ecb37bb707fb8d16ffe50b7b442214c9a74d50f3cb1d25cf1118add3e3b167d4861ebf148bdead2830832a1dc096a4af53266f4c");
            result.Add("ga-IE", "5ca6199af67e438dd0ea0274c76aacc6b85738e032b0b1fd7916c6e5fb65bfa7248e321d46e182127cdc6dad9b430d8acca3584caa3c32294518a4fa3164d931");
            result.Add("gd", "a8e6080d3c8df184a1870b3c062c29b067b3c243a12d1f5b8fb889a76a7cd6e4b19e4486dd7f5503d1cc5d70f062c82db7d327f5bc9f9366f5caa4764dbbf3dd");
            result.Add("gl", "38f3f0e19d3d75bfd28f322d4fc7c96d4ab636482ae7077a471c0502d781d0529e44d108680fd7709d78ba00c72a4d1122eb2499c391a23dc0c2ff842f7e97ea");
            result.Add("gn", "17a6eb303d8a3ac121509994eb1be143d052e65f6e8543f67d09132fd37c591878e350941a2c89c0d6c3ee86a387661f745f00bc2e31e300aa63aaa76c499966");
            result.Add("gu-IN", "221d46515b8151b58636ba0c78a11f3fa23e2c9a651c1e3b551406708b15f9e48dd55213b53a0b763c94fbb4613390699f105148a8af57363e0de915efa8307a");
            result.Add("he", "07a181c46745113173b2ed1be738031e7e7446e87f6ba0ff6f6a31eb74f3f7fb7b4deabd95f8a6123fe7de55a4be9d2681932c4cd74b4fe05db335b854f9444e");
            result.Add("hi-IN", "f3bd7327e284cc73ba81d4f82735dbddb5cf9ec62d521d32c4ef9dd763bf4edb04834a8014259439db222c65298333d327d3838984eaa04b0af8db6a3ff61755");
            result.Add("hr", "3d5fad7fa7a641799183c42dc4010a59f8ffbf850c79fbca249b4fee3b7daabe9f9a4c8e8bf6b73f3697ae78c66cb0485d2c59bcf43ad7d462a5b48365564413");
            result.Add("hsb", "f68705156da78b487603dd80cc886c0dca281d97bfd4a03e9917a8815c30de5b0c0389ad571cdc284ab7a6db78d7eb900f796f9270931d6a70e4ad551ec4df9a");
            result.Add("hu", "fdb572414a47ddcdca875dfb74bf2b9061e0a230fcfa4ffa50c64f8eee25edb6de5e5034746f7a927f7a6bbbe82d6379b01639b355979eed3e9e4c4ce1657ccc");
            result.Add("hy-AM", "507418cef09f4cd4d0d556d393a8f694f38a6cd72acb27634f65a80b5e5575e60acf5c379a87f6a61ac569a5c69f310e030948ce5efcbd3a84eddd353e4b88f7");
            result.Add("ia", "8519aa64660cb70af777ca27d2d1d6428466481aff5bf2ddf833a77a1bc91d7dcac712cd6835c82cd9e8e96f9b86b314b1e859ee2fea9e67469eb58be7bece1c");
            result.Add("id", "231d766630318a58788e03ed1f07e97dafb9723f9c9a1f43c0a2617d25a0214e4b52c7002351c4e100516e41c420d21199f3ce1e84c8137633c764f8ee2e3542");
            result.Add("is", "7cd73e3fc4630a332c6a5c45ab9696a083abde8ac654a7031149b718b5d53966596b0833280c7178e0778a17f1c8c82dd449c7442505b0b9ae43ee622abcac3a");
            result.Add("it", "662aafa94abf0b5b3b25aaf797b23b0589cdab38dc6d2634f05c08aadb2760bd4a7dccfdafd82a6dd49dc84455b1d0666a889d67f174a302ee36330a6ed84bf0");
            result.Add("ja", "4c5c4e7d248d1548bfe10937a412b79f8c9e366aabeab3b18d5262b1a6783911ce1f06356c80a9da389b7a5c173aaeb1b1a73fc2e061d1c024187b3f7805e4c3");
            result.Add("ka", "c4310578c004123544f85ce375bb073ce97c2cf3f435614e4b4a067c725dd4b966d1e8440d0cad9886e70b3e11f7569f56aa7a4c1fdb69eff9968dce02bab170");
            result.Add("kab", "492b25650603c45e81d60e59c32f0f08c99f5372b31a48be3a571b4cf0d6b13d60ce23e1c7dacdf4a6d6caf4569aa83cda2e45c740862186c99d06d7af007e22");
            result.Add("kk", "defcc81962e7db051949e0aa221517718574d5e42dea8785311539b0760251858040dd19e92e0914cb0a85eefc5e4ff952f3e2915dee98a0b3260818618c7222");
            result.Add("km", "497119b386e81cf6783a6134fb9bd1af7676a650763422c2ceadd3cb4dc46e80d9b9bc76be9f69780f909931d7fa0110bd25ee94e49eac234c6a2adb08431c3b");
            result.Add("kn", "0b1984e1a0cc939a02c70a063137d79e45020a5d384304d512f34fc83cca46bc290e88adef7480b7a9b2aace2fe67bbe9f5c9c02538f99570a466401f188f65e");
            result.Add("ko", "4a572db6fb988f8c4ab59970ab22228b5e1b2e40f757da5ed98e602c767f209ae59ef4f9fdc11295e3c877ed877a45122b0d1e864f9a3b97c9b492e40a48c306");
            result.Add("lij", "546cf612a8d7dd99aaf86f17b30914317205a7cc6891f5673e84982ea0be097a0f0dbbe46df8a8181e49ae877bf4e4ab580c55626141d31fc441d5ca425d0ce6");
            result.Add("lt", "f637785126ce86622a55f9edbc93b83e3c2d6418cce9fe6db0903ce09cd6bd7b015eece25b74b4088915a8aa225409c5d0cf5983333255e62a3cc2c2862d554f");
            result.Add("lv", "2b57837ff28530c1eb6f62c504a7cf7179d4efc664403a521f24914e87fda39f7f117855494c5f3fe32690a406f3964ada007261256cfe0e0432aa9780f55ce2");
            result.Add("mai", "c977d62a35c50c6bd0e8bde7e8d91e674ceeee1f5d55f40b7a6b9889dcff53686fae4335b6f91981ac9765d8956dd696e09902216607075629180d7760c02e1c");
            result.Add("mk", "5bddb7195620ba05b97862e04c407ad7f35554dc4eec5ac7bf7a83b834f11d411f0aea40664b4d1cc92341ab36cae225b1075ebeebb4c66ec73f5e1c4a28f959");
            result.Add("ml", "800ab8908abcf884b4f815eb32c8970e4635ac5670a437418d0a46bcb1de44e807f5df3386d9fc6fc071f26bb45f3d3c8ea6c75dfcb4bd64767555f5ba719ca2");
            result.Add("mr", "b67f859fe56edf94e58774f31c91422e3699712d73d8508f18556633b1a90a7671be0080bbea67016095eac15e46b9f78e1a8f941f56a751fea40f21e67a8291");
            result.Add("ms", "3e38d099d2eba3ee877997a933fa39a9e819ff07cca47506d9d665aafab43c29c815f6e35ec387dc18c295b0034c1ae1ae9c731178ec5312f56e80eac515b14c");
            result.Add("my", "7ddc47ad0ed701e15ea8a5ac96088211ac40ca2de6be92e00649ba446787cbde92e8243e20858b4853b830e933629c975a5d2bb0d801c4792f771d7d297045fb");
            result.Add("nb-NO", "6e985de12cb45dcf06e67904f03d2dc417dafe4d5f46f3c8d64da90b71e7202a189fd4a3f0da6609ab57bbcf8d45d056250a8c35869527369ffee17086fe8307");
            result.Add("ne-NP", "2fb3a85c72c47a275ffe49b81964ae3ff762bd14bbc8024f35d86b3b6b11a6998efea8ee86c1e663619d66e9f5892f65add81ca58041695a82aa2f9b8725a92b");
            result.Add("nl", "0bfc8e896f95bab2a08edcc0f624410f38e05dfee04f75995dfdb0a08ca71bb11496eb5955736bb3e8de48124d5660768f546072679018bb42b1308f502cb6cc");
            result.Add("nn-NO", "645621242cc418d679450a4d1a9bd3ac14beb2e4550405c6d201e9bf8645197d25f4dde05920a398ba309754849d321467b9e01d248332b410c1af9119c531c3");
            result.Add("oc", "5bab9a50606ee3f92ac003bd36509a72eff473f5babe4806192bb913563f9261cf45c5416dc2b6fc52f53d7173d8ec9cef0c1f8433e02abaa50386dae915ee52");
            result.Add("or", "9906b6716206f3e48281b726d5fb1b7e7ed2f87e7cf2dada083239dd7f28b0ec58dd21719eb19a85d7c36854d30bfa15c2d8a9c64fb96d63db5b7cd898c08886");
            result.Add("pa-IN", "51dbf604544a442125d6bbec87979d2dad1ef7c58c6f88eba3d98937cf68e06a926b94101135cb07d09cb94f0bf6fa4b17dfa73da33a5ae9cd97584f76ef5609");
            result.Add("pl", "020c5e8bdab22f04684063581693fb54a9fa83f43a4097f64ac3b87f33d2e6e7d27172ae4bd143c5ff38400580d230a10eb8cf30cd49a3c122d0a819e4d36180");
            result.Add("pt-BR", "2d313d1ec361bbde3fdaaa8413089ee74cc97fc4904ab0485dbe7a09c16c042afee6a57765a1bb9cc2fa77bbfb5bd125188e2ece9e26054fa34b3e0641e2a37c");
            result.Add("pt-PT", "638116ae97472ada2253f8c2da7573a896b46481bf8de765077329f044e575438401d2f81c18dde4a9cb56ab29846b96e171259b98eccb63cedfcd6d493dbdf6");
            result.Add("rm", "c2caefb4be14b78e6feaa04b5f304379c2a1e72a1a43bf3c00941b120a9cf1a67c5b3663aacc45a1bb14aa99e46dcf01d5e06b02cf81ac15431a6f916cff66e6");
            result.Add("ro", "59e7de22bf4ee01bf2c95945cfd42ed4c5c3c97fd29cbf8dd644dc9add1163fe22b348573454ada9ba18be9118229dd54447304b5664be637eba01dae2d650d4");
            result.Add("ru", "c10e20d2e13e325f4f86cf2b08920e0f302e792f5d6a223e6bad6525cc831a803412608bbba700a8520452d64d6538b27b7b1367083340d890d2294f1fcae268");
            result.Add("si", "d9d1112a4dd170f866cd462599fefcacf746bd2ebd11b6e9a77453236fe175bd0d700dfccd6882ab4a4c134b533ff4d724263085cd8c02850c786cc5de86dbe3");
            result.Add("sk", "26256f7819ea12e7469236d25f48b6c8fc66da543d5df1eb45fe4fb17f0508b6d4b3b3fb55b4ee6c3c254ed8ea00a1c5ac956489c3da6d9c89447092c06faa7b");
            result.Add("sl", "39bdbfe69e00ceb212bf0cea85e59b8960a8e105daaafbeddab03d1d32ed446257f6081a2c7f80172d901c4e611fee3233299111f503d101e427f9330a121150");
            result.Add("son", "81254345815b5ea6c9156d599460478b8fa9c81c08333138b3abbf7dd5f05296df16da629e974924e16cd1a18585c0337e01d5adac7e01047875420157a58629");
            result.Add("sq", "8c266326fae98eb973df498a1fbcaddc41e7177867b48d9cdf50c186b14cd69657f3a01b2eb14c7d989ca0fc5357749f51dca2cc406ed76a388c68de5b517ebd");
            result.Add("sr", "c064f89b8e39a4f5a2cf9e0cc7fe36d9c28483372b035847f87ca3813b872a452b04052d5811c08f2e10ad29a348a28006e462198428786eb831f94311e7f287");
            result.Add("sv-SE", "df37e049f5aef0edb3278c5b2bdfafd8016b25d83e0de6bba33026fd9a14cb0123380d2d73e24ee718c9bd05880127a96ed1e13afe2f471d9419e04c1d91788b");
            result.Add("ta", "f7b2612ec7dc9e43796254181310289bb364ad772143e41a0966087e5782600b115b25a81daa547584bd4e1a7cd54e730605e7afd94e299b087bac1fbd3fc1b2");
            result.Add("te", "1179890c918ccbec4ee14bf66f0a66b3550e42bee8ac187524c5421f7e9815bad86471bef1f6358812561b22561ff51dd2b39d7742976876464fe79826293252");
            result.Add("th", "fbc53c306949452a80ab17fe56e18c3d54c7e5768964fdbb077ce0f45f5c625c3f81dbb1a4ae3937224d7643fba77b2eb86c58ab0146cf92625311be3707b708");
            result.Add("tr", "e51af2133725eefc852a18e75e8cbc9b3bf6c2c410e5a94b2f08767191ea1dfc1d166b627226a05408a7e57c92b2660fc93966ee81bd86149d26bf6b1914bf86");
            result.Add("uk", "880104b82669f1e32eebc2ab9b8c220fbbcd13bb1862dd566c41f8c0e58844eb887012eec8256f403e2478e72cc90f1d222d8f32c889092548c78a65f1d4d74e");
            result.Add("ur", "8086ff42fa7a7e9bc8a4732111192ce559b294ff6c70ded0f68a26a25c397a95684bc4c39d8564900fbf63f80cdbf9392087afd7a7c600e87444d188468d1c6b");
            result.Add("uz", "5c720e2f32f9921d061893a78b967b03c9cefa234dac1fd34b6da4d0e2e4689f9b95009c49332ee62bb350ed6f2afe267dd33c80f4d536a320d2e744e77a5af1");
            result.Add("vi", "144983bc6b103ca1deda4b6c6c4d0edebfcab53915c6894ff27db7e0b26081dd20d9759f5eeb74044b0a4c81bd14494558c6d9bac8f3156e83c66f6e837e1a69");
            result.Add("xh", "efe0577fb232a14af3824ea37d5bfb445c1238804acacf78f8a3039771c3c865990ae745faa47cc22b6f7f92fff9a794483afaa0c5887294832b39d848a7b78b");
            result.Add("zh-CN", "a4e312f62f5746985784dc34d5ffeff2e190fbfb14a065f181c68d0d6ad08110b4bdf930369d3438aba85277e422a5f641c6bb80440e71a407a6a842a7ebba9a");
            result.Add("zh-TW", "772c53b4b99c0f51f75add990c575d325e30f288b552757eba5285db8fb2674384f0739e851dcad55316bc21bcc3e151a637020cf718fa36c5a9155af5b033f6");

            return result;
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
            const string knownVersion = "60.7.2";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    publisherX509,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    publisherX509,
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
    } // class
} // namespace
