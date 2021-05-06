/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2021, 5, 12, 12, 0, 0, DateTimeKind.Utc);


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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/78.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "40818ada3ddbbe935311c7a684c7667719d568758978204ff07e72a51135ac6cce21afe6b37400246b3c71197596e211d06023f23d36415d1b0b995a67ffef23" },
                { "af", "706910b0663589a20e61e068842eefdc9802ef5fcb893ae72fee6e7565e739a65845d9dfe5d6eccb990b7a0e87f8efe35a27f1a0185ff606a5ae7ee084014759" },
                { "an", "67483eb1ea2dc0fc654a4c101686e7f3d88ccfe3301bec59d357ba055ce7489e90a2658068a4d5b61b5c50bc15cb9c0b9c1224da74ab7553739c003bbdf37363" },
                { "ar", "d8539267daa68c9966b7bae32a37693220e5f04b0554fe12280e65430c5b17c502dcc2d564d5d003fc9477a98fe1e9150658ef755bfd2c89ae84dd9f8d4cf842" },
                { "ast", "6f4b14d5de9e6d1f8253bf76f4318bf7db28f42233edfa0249ac4ac072fca1e4b85e0cc88ec15bb574ff553fe8d60b828a13d7fd5d19479798be875d9118d688" },
                { "az", "b704b78c627ff653801f4ee2b7e7fb60c9127f284c3b9fd98e45ddd2159688b2e35bb62f695dd76e47f2b2787657da706dcd460c0135190d8b5fe7c9a4a27aa3" },
                { "be", "aa8ab92fb9f741a1e231f3c1c9e1953ca658366925cd0aff31e9677c446180f7dad9f090ba52118f27bed866f575df0684eacb29243684497e39a3bca7b25a28" },
                { "bg", "f4699221cbe2aa916fda5b5d3636cf1d7d8f44a7dc744dff937945d8addf1db618753a974221d221c96551c899f4d8e9902c383589b89e28a1769f623a79e557" },
                { "bn", "efdd4d3e3d666af0359bf63d8c527d4b48e61dd51bb1d7c5637183a4bd9afb3eb98bb76082dc04e18dddb52dc6db9ce0fd0ee4a12fbe153a417660be48527b99" },
                { "br", "c09af1b6d885fd3ff6e84c79a6eee5225a2989fb34c3888777702cf788853b757d5544bfe9ba1e0de1a564648e302bc225edf2d127c75639b3cf66b46f2a8188" },
                { "bs", "fa2c2e655587a03a919119dc3cff78d8d0449e8ded0ac3d3db0f3a5852db3dc684647e4aa8c87dd3875f04b7fc8c287dff672a64d47b564787968224dbbb847d" },
                { "ca", "34b921faa8cdba926b15657e335fe3f99b0bf5618422df736fad10d8f391f3c968cae689981fb42997b063d8fdced3818ed6478ced91239844f5b0f0d11828a6" },
                { "cak", "36710383d7908a2de543033560b4478acb60ce7a70db135747a75128d4703db2361480526f11fed1ff1e5b2a78ef7a0e9823ad5baea45fcd0d2cea121af90d77" },
                { "cs", "be61e5e8e869a4950c0182c0d2b5f33764d2fc56cb74fb98151d857f9cba4a52e5f818a10f7882260d970019264d235109ede85492573056e8a80f803c6368af" },
                { "cy", "20a75de01a95e22e08c9d6b28f7a06b327c638e2bd50de082eddb3b9ea134ad26b2e124853675c2ca8b181a2b3495cb5a54dcf61f6678c0d0441a00c931029b1" },
                { "da", "8d17ddaf848453f42966d0ba7bdc9a9fd8db3cea10e49c13fa0ff1a3d6d04a1fb8db72b69b2f0373007adcb0e4f4559d4eca4c775327c8948c5d8858bef72f69" },
                { "de", "59b11efc29d99f5c1ddb5d47f771c39f09920fb2c6b29b88733c4472558ce26918479f01b69b221c8d4ff801a50a08d7be71f874f6c9514c866436a0832cdea3" },
                { "dsb", "e9865466d6ec144f359e58503a88b1e4087b3992f7b7cbdbc261f1a06a75c17223cefea3ebfe433363161309e19a137f174eb30c187deb76a59f1f57a033ffef" },
                { "el", "d318ceaeecb6b8341f6661f7bd8ffef19aac59d10a65b7ea3aeacc681f7fb81e150d9353728494191b442225035f8b86979f9b18241c69096ba9c79944127e2d" },
                { "en-CA", "c85442b1dd5aa527867ffbfb1014035473c16536ce2ca8a8ab06fe50500d957cecc14ad0f55f4a3a4cabc4b22c4815719ca1e1f460b4d01baf74fbb09a0055bf" },
                { "en-GB", "104799e89a7420806b2569e337a1496a23211ca3a4afbdbfad9a95b29065ff0e8eb1fee2391d09f954ecc868040787ccff3da50fda70a5a27817ea6325a96703" },
                { "en-US", "d65e1497a59c597617e0b4cbaf669e40b00227385640528b856c9bc38835dbc2ba9ad3e79a1de90e603f7a17e2df1f32116ce2f31c3fa9e744764a78aff14cc3" },
                { "eo", "f7a71b40a7773d35a91153b04ce4716f80f2f5ee99d0917092f89734796dd3a4ff4beb3bee483b01919d9b40aa098667fdaabb9e17d354b9db5dda76bde5a9b0" },
                { "es-AR", "545016b1e711e4d08f0043b9b9a0cdcaf4d4409c887724b242e9d515b34c8c48308221182859556b82b98ee8ccf0c0a34edc6b8fa599d60866ad2ea902d30c3e" },
                { "es-CL", "9206651ed40a5465cb22332e9bbe29c92d630fc0b92bf59caf523ab37f1f94e7f1d47462166ab3f837d134dac38171b4e2b2eca3524a7a384fab3633bb57370c" },
                { "es-ES", "c7b0cd99f568340cb45ba05b7cc2473199f75240b289d6d294f0217e60b989e6bce967c45809650800251b500123ff7cfc18c741d13c554ffa14702eaf3e152d" },
                { "es-MX", "ca174824df425a0c882a75b0e95022ec336377f510695691e0fc4aea174999a2e74059391db51baeaafc732ef352911b19d7c6af484b712b64cd39b28014548c" },
                { "et", "8d6476514a10db06f65f0a3e16f23b02510ca17e4b222ebfc309cf0437283105a24f50d315b53d42f7dbee201f4358ab8af703c48a9ce70911c5f0730be792e2" },
                { "eu", "90cd9dbee8b5dbde3df1f6afc86edabade45299c23b77c5ae082e41a7ae1908c045cb49457fc95f3bc8ed726c5e71f495173bbac7c2bd3bc0e568c9f6758b47b" },
                { "fa", "31e71d08b4da9fecbcf6ba29e8f4dfd49dc63c46e739395a45e75749bb1abc716902562241b8d12ce102df9d5641e5de008564931a11645f50b6ee0ac0a06102" },
                { "ff", "30ca9166c7e1075226444956a7a74fecfb2683250a01fb68e12162cc48d6dfc2c1df99bc355b588baa9e059ce8b78b86285bc40ded9b58a285b7db2ae32a6cd4" },
                { "fi", "cfe2322ab0cbbe6d47a217c925a83addcfe459eea2f5275ac9b5acb0efad177546efb68c648f7248891da8ae68176aa9c76d554dc28ff5b3a75343c065fc3d51" },
                { "fr", "e092ed1c72129fe6fd9c6e73f2f9564caa484e1b9de0ea7a29dbf7723a2e78afa64598a6f8e413c5b08a0a653a6af97afaa1023c6241a2e61946b247fcab9272" },
                { "fy-NL", "5d7ddec2ed5e2c5bda00a0d1fa710dd859201fa9cc00a6eedba7dda41968561c0ec09d0c86dce5543a8c12615bc1fa5dca244c6e22c5cd5b34f4886e8f80c88b" },
                { "ga-IE", "1232b4892ebda267e0e0578d3f88d1d5589c1232efddfef67764bd5a2da2119cd171de035bf5917d6a8ead26ac7f2a0b8674f0c84df1cc8fb2737640aecc096c" },
                { "gd", "4c1cac8a54e8c66d871257f990e73beff32d746c128568c55900c9b7aa94d9206e8b958fb841d0e3ca385f1708b6979d7986c8e8a43756703f4af2a9641d50ae" },
                { "gl", "72819e2c92a1e4bcfe0ed01c9a95983589edffa2a731acea5f2a3a37f3927d7d30991ca27ca5ccfb29705439a6056189f0ad8ca5bca2ee1d7121bbe3d9573161" },
                { "gn", "5e93a30166c4f8c5fa708b2a97ad6de0ebcede3c2e65b42b52c2dda847e3192e7f5aa24eaeb11d6aafb2f9f507d7fffbb0ab4abeb53a826f2791cbdcc0faa700" },
                { "gu-IN", "cb01cae1f503ef064804efbb328bd6577c73f8fcba3e1e1eabc1d93ae939a2b10464bb9c853d0fcdee242c03e0d4c124188ddae1839b6336b753b5442abcda0a" },
                { "he", "909b8783e71602156c7bed8e434e9b2b02d15cf5e42c449e11a2e983af09d78115a14ff0bc1dd278056d06267ac0731f669d54ef7658756a3cee7db9a73cf7e0" },
                { "hi-IN", "d164458e294eb7082edfef91ca31d300b607ad84cf28631ea76f44f013b4c69fccab20747c236fd5449a1be3d332f0ba9be5bcb7d687e70b93f9174a288660ad" },
                { "hr", "df313bdc7ab2d6a249004d3f6490f765968b59b29428a1b32929478870a01932532e68a19454091f2a8a328f3d8666a7e1b481b09924708dc4190049898ec7c0" },
                { "hsb", "b49c7dbfbaa7a944c1c03ad0dac32b483e667f6979396194b61249cdf5736b293f16696e72ab4dc2178afc6d425b7da7880e685cf403374cb915074d7a10c4da" },
                { "hu", "b1a05750f6c494e03e5505c0b6a2ff87c705700ff84087385f81e98195f2be3fbb4dcbb790e16f27d288ff50fc89464e3050d69c907fe34a77a076bb014114ae" },
                { "hy-AM", "f470f08aabc87d741db8c36b3360945e4cc5b10cbd1ac15e9b85b2f98a5e0c250347ced3b94fe96d57b4f68f829f2e72dfd55b9846caf0229914c2ef7f77ac4c" },
                { "ia", "3174b02543700cbcc3fea19c5c5c2a9e667d5ba2df994875939f54eb6c2a46fe4923f53c60ca3c367534e28bf27ed06bc1fb17a85d41e5bafbc46c5198a4f9e7" },
                { "id", "da538e6e8c12d2d9a176c3ece133a1d0db3885d22ffbe018de6618133228940e441139230ce4dcac3398e121244f7de7cc67e149816c5f5b82c8792c65902047" },
                { "is", "6829003b66a345e3bedea609bd3c3a4bcd508d460ec7ece1245345d2f33132a10a53c9ab1e50cd4afba492754cfe24f9093a789ecf0ee72615fc95d2b66bb69c" },
                { "it", "4b58ec34dc860904344cd66fdd728ed4f03e36560091225a52a47c4322f70320d62f79e9d24602db3772ea43d7d1e54bae5df61945091e6bbb004884c68f2386" },
                { "ja", "7942dfb04fc1a6c9261bc1efd7099bef7a45e9d6cb81af6ec4c2c2d096c955d33632be269c0e901f5ad2aa6dee10c6b9814bae68ef3b23b9e4c9ed22f775f1f5" },
                { "ka", "4737c471a5624171bcd4a74e307c0efc6a4d826997442c98968545e2b931a1a220ad8d4857375df21cc7d9bde93203564a3bf49b6f85956da454c341b54247b0" },
                { "kab", "35a9ec616a7877be58bbdcff9d098f8049a2fd6e822e501eb6072a1812fe08cb6813b32ad730ce6fcc42e41679dd0adf948e15f317b92ad651cadab77a8c7487" },
                { "kk", "973eceb0cc09d8a0b572aee3ee1791e9818403d2e0780a1929c330049f131d9c86484d1d0a7858253cdf7f4aa59e0f1906351561cfa618c4145557afe6175e36" },
                { "km", "85653c25b67e155c7335ad1d6c97902e901df3c5566dd99ef2b8c127c156ecd607e978feaf5c3c9bc2a80ff1d050463bd4fd396c387723503dddcc4acb72ef32" },
                { "kn", "a2526fa3d079bcec09598172361274433fef774d307d6edc6563ffaeee5db74d30b2bdefae366a0f78ede1d7170332613e156db88f68033a4c427d834a2cc8f1" },
                { "ko", "df9063f5ebc14a1d0dd0d4fff1f507e421e6d128b101c9a0ade923b75e316dba66aa9c6b48824cf6fd920324ca13b00f1b15709a096a06ec184f01915f1a7cd7" },
                { "lij", "c7edbc98a77e607dbd410eb3bcb732c0745d8ee811fad45d9ddd95bc60c45a19160d13f235b8895cc7dac65e17f5439941eb2fd8d61da1e4ff38a009aefcb77a" },
                { "lt", "6ffd00f8c40ce4cf2012e21aacaa9f7a33aca9f95a416827e8635fd09b3c8dfce3ab74310ddc65b65f1051bb571828e4a61054aa869453949376c28f09a0fd92" },
                { "lv", "37b5392a0d49ba1f899c2f8a6c56ede1b3f6b04f493edbf98a261bfa1934bfebd8f2b983b1b89f4590e07d02ee2630b820d2dafab4f91004c65aca743618dc68" },
                { "mk", "0a51699232d55ce4ec9c08d7aeae00ae8630f5cb45d35000ed6a256c32cd8989ef6b0a02a9887fdd81fe5bccf25911b1cfb7ae3efe43e79b7552f716312ef748" },
                { "mr", "4ed437821163b5bf8e7306fdfbae16daf8544cb01017e73c4712ef0dcd45ecb1a0d10af8ce002b61b22f407f2c2a3b1a24253b7a63874356446d4184463b9823" },
                { "ms", "1d49867ff444784460c97530fde2634ba758d1fae4e40efca820be365d28a025faf51e0d454dfc5a6183b1bdc2e851893a6ceacf85ea71bae6bcbe70d95c7f80" },
                { "my", "ded73d8335723fa636f4ed6070f3960c35c3f84b125be08ae8bb7fe1bed1e87633b901c07f4b4ea886f8181fb732a88f967d4ddf28f9672f4b8dcb15c4640a28" },
                { "nb-NO", "b86890236e75d7c487c4038bb08df4445e756cdc7bc9ee6ebec93c0705906df7bdd18ac7a9363b30a9be8c850d6bb30da6b7def3a792672ac771f60adb01c123" },
                { "ne-NP", "6ad4d4f85b7fbb50a175195399eedd8d09b83458948d33b8f9dcabd47f52db45da40f86ca6b6837d77617a411e436fb03a6fd1bae1b923de6a8ce4b73b0c0d3a" },
                { "nl", "fff7d0228b4f1263835ad4d6802c078607ced20b6c5c3b55408071ae0da786657b0892e7a0d2ee70f59f0b64122ea9f679258bd68d3727686578dfd76830e798" },
                { "nn-NO", "6f72a211e367b712e98b15158c35e2b06304b1fa2fcda6edce0b69a329ff65cdd821c79c9a1ecc80ef961f23b8870d38194cc20210db584993b43bfbb4ad72c0" },
                { "oc", "53cf2cbd148790a2f00a63788b4420b1b0a5e98f1fe370f0daf87e476be52d10e42eefbc6de26bfc4e71919d189eb75529c2f06f1b3f2661bf18568b36ce0b32" },
                { "pa-IN", "2d45e35c7922c34d6fefb336e5d7275aa751c86c8d9891f379f386f4c42893543e3aafc0f9272ca2ad56c4d464ac3c146535e318b36ceb7f602b07c8f77ed011" },
                { "pl", "d9bdf1997cafd347008c04f2a038cfd730f97056a78e3576a755c6940d186a6a1b9c13272262e9fb67041f19cab04da7fa8af01391a1ce5c7fc95b80c07c1e1b" },
                { "pt-BR", "5515cba3ed99e78b840f517c1d70e47297247793338fcf64ad8fe4cbfe9a3871c835c40a4fd0b9f0879e7d066b711d7e0c66e39a9af40a659148f7238ab20ecd" },
                { "pt-PT", "daace0c8d7694eaab3514448285248812387bab74a9e99576c8523830f762a03af7d8519e85d2421c436b4c8b34ef9d3de00d16e6161877630d3875c27d01dc3" },
                { "rm", "b2ec87c91909737d0cec878b865dc073c5576b1300ae371d2946def85874bda5eab5058e5984183dce635d5f745672e05f171c120f5c3b9fe76efb779012caa7" },
                { "ro", "6a1fb38eb50eb9e8bf8c12b301193ab60c3ee0bdcb68886dd78aad8b12ceaa6d37463ae1c66f849a5690364c8420add414546e2f2473477d0371413851f0b512" },
                { "ru", "1c2b439d8e2da57d25a306c3dcbdf6169877ef577110f1320e8bf99ee065e0f0869942eb0dc6b4fe5db43da07ac051c9b2b4b39e66e562e0e77c45897a3aae4f" },
                { "si", "5a03a8038cdbaee52aea44026c5ca8030832c4a1375539d1d13367c60abd684c48f99ed2f893d5f4e5b6e3d08cdf0242824c8db9572fc4232d5699c295007eef" },
                { "sk", "0f7a7da97ec02645a6b48f0c3c54dba780f02755242b8ea02703b70b3b1c1a13826dd3a825464e5962a6b84041379ceda7daf1e6af43621618fab08023660289" },
                { "sl", "29576924abee682ec42bbf65d0cbba6122c4c879624077c3699879c746b0b2189b34489e172fa531b8083f8523b34bfc0355b3525b3376941afff1181596528b" },
                { "son", "1590a5107e6bd071c87b35b80833b5ab66baef2df5e6e05ec16957ca093c6b9f61d8a437881339c94e556cff56c57507c2ed69a1e98a84606b4a32e6ab09ffc0" },
                { "sq", "9d37e3f52c610a159391bde117132feb2064a9258a51871a2a314dcbf9067837d5a8cacaf782cd20be06aedcf0eb1922cf6e01e96f180b16251795d79227ea9e" },
                { "sr", "1015ea929b45ef84a9b22df190c54a52b86d7ba595096985ba3c4e65a5c10efab29b5d07741e718864a08494c9bc82f6229e88ea62119db675b67001124741f9" },
                { "sv-SE", "f850174e4a906e009dc15dfc8dbbc4422a9a0febe34d5bcbf5d760e72375e881bf71de321d012745a524bce71aa588cbdd795535d515c268c7236a259b15079a" },
                { "ta", "e66dc4e73119156aa7caadf11f09ec4e2c592912d410bc9df35c49c3dffb8b4ce29b3cece14fcbbe47240346a7df19df84f2b7e25b1b6094826b967067bf5556" },
                { "te", "6dcfea5759b3decd36203310d8d354b7cd39647a2ee84f2910fcfeaead622368bd9ea276f67761ef5171aacf77b16712702c16867c7c7af611bc0ac63c24cf07" },
                { "th", "1ee32b9dec013636ffcd9ccd224c2cd84540ea5611b76d3a34f6da8be4926bf246d1fbf9b36075f54af64169129a068bc1767198606f2beeb6243d4f30ac59bb" },
                { "tl", "b1cbb691b298316299cf14ac8b9ee52f893ce75124f64ebb820caae50a405e469eb049aee9140499ec752cb22a4c5cec34b44855bc4e2b4aa7199d22ded52e96" },
                { "tr", "f98e01c4577a547913a9b9be3888ebb7ceeadd4c5355000f2712d40f8348a1b5a8a9eb3f8bc7a670ba615f2b7db0d986d7abdb7657c94e87c339eccba9c247fc" },
                { "trs", "26f27d0234e20ecbf92a17d730e28d1842da754c4ab028389b95930bfa74ad401b1a4516b0a4eaba148ce2ec68a3f524609e79ba4fdcae5d584dbcd9e75a4027" },
                { "uk", "6c6060736c7dafee2801fa296ac7ff2117f4fa5da257cf5ee92055edc4bd3b751257b538f4b04e00fc6d14f34640eea06e482f771b9d732cfe77260e2ffb9ae0" },
                { "ur", "d24765a360f243df16497fff0fbca71ed728e3ff1789a4380aa0c1495631ea1387976e9aa2c3326ca853668bfa0830f3b254a7bf79801179591f176ede6e7289" },
                { "uz", "b138298005546afcbd0f9daaa2db423a742bedada337d3ea2d55891fb214274661f3bf347814992637c6931994f5913baeb920422c1d370d51406673a9229a22" },
                { "vi", "09f317367bdac425ca7659118c4d66203f27e807d3c613318ea7a281bf0cbb5a6052c9426635a5b7d015950c5cf1776a092a8477f8a6a008a065ec8ed0810a51" },
                { "xh", "0494d95952e3eff3f587a7ba47ed2e4c5487b54e445b999eb86f76d26811fb2d8bd23e4a7289e9c6d8d42602c2bdcb1cc19799d8da0a3eddb053ac9a88c10346" },
                { "zh-CN", "90c7ec86a05c550ebbf5f8b02b4fe827eadd8eccb96ea9ad832f1a9635f06b58859eda48c7c355ac2939141ff51e7eaba7b844de1a6ef4f464c00331997447aa" },
                { "zh-TW", "2c065dc94d0845585f21988cbe06f9ce266ad4a82ecd37d996d5e26ccfa57ac5c336be844ee3a890884498f48b4c744724ddb977fbb156aee6321a480bc1417b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "5114e63200c833478b161d620265c826cf92c3d4ef153880f304a6506fde4214fd32254abdcee7c322424f8e3f77eaa2158c2c3809b7cd02011a52f901763f56" },
                { "af", "d143c7d4ca956b3acb4839ffbecfd9cfa7e7239f3f387c061c297c635e43582baf3e836cb9d4546ab9c9c332a133edcdae709869c35cd5d9f43923f463b8d015" },
                { "an", "41000bad22617c18b055dda1ed94de8b8ec7a8a54a99a43bc85e1c29a60cade85083ffb371b94a41b4183300b5ebe3e38e5b23fd017fd4cd4a0dc30dccf32ab6" },
                { "ar", "b6728fac1d2a23861c75f5ee915068a32fc7a059d235a50b01d8e62dd6db3b132b5b16e6face92ceaeb313511065b27fa033b277a75a01c33c4ad19388aca21d" },
                { "ast", "0c5536f2ee5c96ffca0532fff7625a795fd9f9128d3dc7ffa0acb685c9c22124daac23637ee57a03bb7bfd25edcbea5cf2d06962f491c522e39b7e6f8c680a78" },
                { "az", "e971df35167262188c3e74f69f731a8afb53d1c1f6c519d88d92cd5c095c86b007c9a289a7cd64c5eb9f6ba9021c5aaf9797d24ed9afa317ecf69d6141c4907c" },
                { "be", "ed3b9298f8cc1aa20db3efb1dbe0023c1da199b3c4b6bf3ed94fa2bf928ba7b15142655b13c3d9427b7dd4c8dd7ee11d3ffb4dfe2e51d0faf7ee874d000cef98" },
                { "bg", "de00dd36ed22a8253ad846a8e366bd0c52116e84a2475453fc8a909b0d1c8aab37c2c4bc9d9bd42aea83b30df3a7e42a6fb966ad869ece6913218e6914f9a702" },
                { "bn", "b2069f65fc01307c280f94592bd0ea55372d819c377a751129244121242a2e070933cd0e9fc8dd6f2ad2488f0378b0e1d80822d85abf5ab4692c7e7ea320727d" },
                { "br", "7dc74d688df57a4d2df4b1192c0691813655590a847eba6cf65c7c4a361e059cd67a1ad2523799bef5012566704d3879efec684e568d8122e2a68831b6df7a5b" },
                { "bs", "a69a9c4aaa55e508f2b416f100bbe3e0724112d97b53a0cae5d1db39c2287e6139559c42aaafc5d657ecb9795bc9673952d40206ca2e53524d5f2e7dd6b7c166" },
                { "ca", "672598fadbcc222f5e6bf085441240f187097cd05f0bf60a2d415a00a4fe6d4eb1e5ab9f968b04d3965500bd5f4115dc407accf8239be84a2ca0d877155d36fb" },
                { "cak", "5ebf71ba0969f86ba7a77aee48cb58f96f37901fd6c9d3d05a8288e5d7080c2901dd90bcd5e6f1f84a04333b597e79f5f3397540898df81e1720175ceb0df13e" },
                { "cs", "a5b01e57b1a88310ac75cc78cb754dcf687f3094a7ddda48e908e90b0af56ae61811f6f4714bb0fe17a327fd85ad931474ea24be4c879b1bf4b1ec3814076468" },
                { "cy", "e213a762a1791b588c18e26264233e000b0959ee01dfdabd69c4ef19eae71562e434755ac9e08fe928c8efde10a9e047d65d390cc628f8da9b40e614e4543fe8" },
                { "da", "db3d9bccd64ddd64c2d327dec691e94b8c12b7ccc808a889570d865c0f930f9320520e29c690c8d092836fde635d0a55a98c278290f93256666be076cf98a16f" },
                { "de", "b003a6bf86a33a4f1426dd3648cf22aa6caa471e4f46ee0137d2787957b522e3fd31cb0fbdaf441c8eda6a3a4eed9e4d0d4f550162699ca07f4a5112f8237430" },
                { "dsb", "9e18b324fe2d9c6705461f768facca08c5acd9d8d7aaa7b887cfa4669cf1cdc4e6c6292cc32b2cc1df5f158567698beb97dc5a4c9754cffde4503048965f6198" },
                { "el", "bf790251f483d8448ee9b86632fcd5f10f901267bc862f91ba4a216f51811f26873e35dc74decabe539f9d21b5c5d01f66749d731836bbea0b099e0482303bdf" },
                { "en-CA", "5a7ae0e0fef689cf07cbf37dfd03317d448173a1eb2893aafc7ef0e4aea1bc06aa124362d264f7511b73a2a9b43b8b2cf826ef096066dffde5c592420b236e4e" },
                { "en-GB", "42aa2f71a408bbb386ee55012db274a544c80d04a8069d796a12937b3d6cea2dcb0e7214ec9f8aa59450048dbc68076d48489e8189d43b834c24ce6ea5b3d1cd" },
                { "en-US", "143ee227efb3a7aecb154b536495cfab7d7c2d01272503082cae88e180e291146e5c63c35006e681c8a1e1af5b260ba85534c10a0830d1a7da5cd82152f1ebc5" },
                { "eo", "eed7ec1405264c5e9527717e8758037e93a8af83a7cecae4e71d4f98700aef3bfee451ed779761b165c9541aa8ef58b70379a32c4a45d1707e11a9c5e8ba7634" },
                { "es-AR", "3de76aaf0b1fc394ce9fc062944592383b0671e59879fbc934880ad183d1ec1f54ce1a8aa896902bd45686dd43146fffa1871810dcf4dbe5bd83a540f15bc015" },
                { "es-CL", "b7fd52e61e70888cf05a2bc3d5b3da7e257b7f8ba687a7c9033a14c8dbd8618e9d293c2b9dee2a9f943676e76680c2bd0172abe451f09d9401b2fc1109b8138e" },
                { "es-ES", "38df1deb7595c9fd2adc07d830fd69c2367a5039e390e26bd2153ab23fd1c01463bc2e7594902571a075a63a274e054d17b75bdf16147cc4f47455b1a20c7539" },
                { "es-MX", "ba470c37b7a7c6cacd19a878817062397dac0c8870303d8a33180a94c94b39b93f43089b60ee5cb1fbcc08615b38e773ef4d9c5a1c2da0c9794990314fa7c17c" },
                { "et", "d7b8f4a2e7d2087feaf18be5811d5bbc654005713fab4a6ac764d4226e302a2700fd6bee1746fbc505281575a24d72559642cdbff036d292d443b049aa7f4096" },
                { "eu", "277e8c38c8d2f9339a93e1649f136f576a2ab1cab732fe354cbca555f1440ab400559e0b914518d1006df1069b8f608541a924991096b24864dcbdc2a0b036cf" },
                { "fa", "614f1d3d6ea3570ae4a5f09e5726f3ab5926e84f0e1adf4275a1d33f282f0f23d7842fd65c09d9612ae1d63d93d9c4c0baf248cbf22c5500786035dedf7355f2" },
                { "ff", "92d5b2d8f3c9cad06860e401d36e507343b83a7116fcfe3871dcabe64fbc0f76b915c840a7f628b081c1df7ccd5558d53101ab206d2dc0bc0d876ee9da113ae0" },
                { "fi", "cd50769c9da51383b43c05803d4f938564b014c247d7738aa60fd552b9dd730b401401c7704427d71747a2514cec892f538764f7c4164a8fa8a9e8b82bb982dc" },
                { "fr", "5c7987e5c1ae0eff99a3d5332d489858fd5a13ec4d57eb632771f874bf1d2f0411893075c9f7947ba865e190eb533560528dff80b4ea0384b368973fc9d1d5d8" },
                { "fy-NL", "f3400ae5696ed1c6a31cd80d85b9548f850e464617751e33688d34fb0c71da70604517edac0590df0d046d53738a4a5fa21c300c5de8b092b6d9503edb9c5083" },
                { "ga-IE", "4beb9ff709535e134bebb766b15f962210e04e248582295229e6f258b9e630ee78d8f684a0e18600485654e4d32319e25753a00bcea4186476c672016b255086" },
                { "gd", "8cabdcc4cfc2aab47148706914f507352e1a593f0fec698b9ccb150d807cdb54c6d863b2f9626d1ed8caf7252ba5c097303fe76f8ce60fb16c159f264a46507b" },
                { "gl", "d1cf5a94d37b4d13b352a9eebe16335ed186076387b566a02c3dc2f53f1337953cf705a0a48460e34612fe51178ba527bc3da96d1f424175684bab70063373d7" },
                { "gn", "bad436d468270852f773f6892b34e8ebc81139eb26f314fa00f416bfdca321e077c51c094cedeac0b651c66396e12a6e36afd59996a85813da1e25d5c53fa9f1" },
                { "gu-IN", "1223c73ddffab5b1f7e2bb6c24fc41613f754ce7caf4a91e80b0f8ee3ca1fa5e31f574daa713099a164a9c059f3452ca5cc44bb3ac6eaf5b7a533ccd5d361bff" },
                { "he", "4fc86d6b843dab38e5038d68de53f171fa7d4bab404cdc38883fca7f370a1c1f1c8573fa5cdf2af7b918334ade8a1b5607ce270b374ce9a2ce6f5c6576164b93" },
                { "hi-IN", "a0e703fb31c6e887ca1db0510422b50cabca72355a0271f970d2886bae7370e56c49388b22a19c1ea315dc70a764e10a2cfeb7b59a57f4a65858cab18c9b4980" },
                { "hr", "0fbe0405a8ebd473422342bfeadb520373ea5a9da203687660eeaaadaa02fe7f34e4f65f4daf54bee96424274a2ebb38547ae09e84d557ae594566cad63cc466" },
                { "hsb", "de4666e9670d56b70dfb45a9631f30701b7c003e2840a11407f6209631c412bd26763157832ced88a3a1a48ed23d3ec7063e4d7585c51854479fb7b26c0f7691" },
                { "hu", "f9f47d3ca000cb42818f7109fdd6b191909b4cf57a9d301e408092d21932836ef823ceefacb961a598e2e2774f74a5d8f06df0ba9f298c2acbf6e6f9cc53fd37" },
                { "hy-AM", "7a1343ce27358c10bf1800bc40402b1737a137ed7c42a8525f47792bd2021de08bc1d27e317390f9e0cc3fb6cb7f7d431c72f734543ec56554b1a6ff6ef59d47" },
                { "ia", "b23aa950851139dd62a7520f7a14194e054cf4f20a30d0599dc6011515b2fc078927d798ca17489795a208d14ffd6299a898c212ca0111374d0a567000c0b564" },
                { "id", "af3ee312a8efec1704d64eaa88d0e8582d10a85dbe6555826f4f424528a2a8bc56e14b9fdc4a645bce48e8f7bd58822eebf9776e89b945a910af7d4725886542" },
                { "is", "186e92e6f246f6cd6cb04d70e85b021082f8bf1e638610e158768f968125847914db104ab9cffa83188b94e6c9615ff806731487cbc1e6558c5a896c98436328" },
                { "it", "055bbcdf0e6d0f6964f61a44a86128d5d43a668ebd341191fe22221e2a3f20d2bf7be3f862eff7863a1ecf04dce18bdf226c01f89359be42689007ef24d96661" },
                { "ja", "dae47a143884a2fff8796803f48915d13695167a3efafa302409751cfdfa6eb2c14469398c43c1a36f3dec535e13704773b24edf9493a73e94ef2e8069d031f6" },
                { "ka", "51b194d2b811ec2072e1322ac42d332d63876f005b811cd7b6fd9a314354f1fa15374a1303600d3e672d7919ac15b894665cc3bf8c6d66a90436e5e94ec549f6" },
                { "kab", "d54dabe76706b8e4ff12a2b402dfb8a4e3ba513138ed7d9ef6f4600457dc4cdc14c9f1529ab95374c5e3e9f3c58e6b7cd6f462554c0bd66a8db5791e578eaf96" },
                { "kk", "bc4baaa42cd02e5ad91c6aba7268856838bffc219be008339107980002438ca09533cd02ec73336aad6fa8945a906aff12db143a04b40286bf951e27d42ba90f" },
                { "km", "c9f82758447e9224ddf17f3c7dd0ffbece258a23215a883b2ad077c6e9e1b5e5d273e50c784b3f2daaedc65b82854a2c2967f0391cb2df8daf41ca774706145e" },
                { "kn", "1662e556d5b0003153fd1bb8df4d5f9aa7495e931f3476f3c37f21cb16bd9718f08faa80dec594234d91c773526d89b27278a4e9e5ec9da350b927c45f228e05" },
                { "ko", "1eb3e314e18b4118172e381ef7a58b780d43531ef42105965217986207bc680ba063cb5aed6c6aa2a3ccac6da9290040311cd73772cf2cf17a1e6a9316fc1b47" },
                { "lij", "732932d7b8d1df9e8f98ae15912afe6f4e3782d7d281abaff3293bca902f6c95cc66314d40ce9852d6c64f4010153b70f49f57cb88260bbe489b2ce13049e0fa" },
                { "lt", "95c240292a45669cc6c37f305be1112fd0b192d894d5036aa38fa4aec0044620d4b18f7f6f9ff0387304d9066af12e95c089fc6ee99c7366504bd103b98e06ab" },
                { "lv", "d568ae4e2a25c83e4cb9ee53ccd4089df315f08d4239c686e96d3187c7f8e13fa6ba05aa53c3a18b85719aa2866b8d7849eecc30c68111f9be0673646ab11f9d" },
                { "mk", "f52fd5744639b2e77ebd77a9ac7a599813126b04a2634faadfc067b30efb1647094b184e7bcc956037ff14110913d5c4da2f113adaa7cb061e33074c51f5aa71" },
                { "mr", "0d6c3ff497bab4b37f1cc2dd8b713099b8f9c4829c4ed56c3a17b8b564c04fecb848bffdd333658898a0bbf688711f50687a4a8dff2cb227de267e493d0f789b" },
                { "ms", "74bd086d60dc3a0ad73263808dcd34f77f9e83679000e6c0cc300e2810323786488c886df6f0e7b998b42b881caed7b801cbf638bd96d2e0de6b1c7f6c8650c4" },
                { "my", "ad0772ca9f95d3f1190365be7ce7739ac9b89a64fd52bd9ef5c043819ba3df670d924ab8194317d7e45fb1b8070f6d858f86a05005c1a02bf38c0aab041698bb" },
                { "nb-NO", "7e821e5cc102b13a0607ea147277d8e67caf15f1e2b22706eaafa4a86358d331e6d45d1a29d95bdcb4478ad0d862cbaede8ead687044e3d6b192d6f3458b7150" },
                { "ne-NP", "4bba0a2ab570cd0e873db4e8aa5abc9201f2b10710a4d164f95697e570a619ec0034339893329b0bdfb10e393476b765ac09bd25a7e7944f91ab78908fe650ac" },
                { "nl", "c479368f8357f23efdbc574ad0d5c24578b81cd6cbcbc2bc1a97e8db5d87e43df3826850ae93b62f94730e4d479bc7d6ac30f9d678dc75429dab4407b937b4bf" },
                { "nn-NO", "527a77b54b4b3f090c55f7d4c8ba1e449836e442cedf8f40a437d32df8254ddb27b6867a76fd639f98181f2297b64d0aaaf82ddfc25ed97788b4716fe1295a4d" },
                { "oc", "7056b8f17413696956f46a4110468c696bdcc29692b3ec214874e4754f991919f8917bfcab711216217226a394a3f8ddc8a092a381122ca9813464e679a6eb88" },
                { "pa-IN", "ca871ba5ae8d267333ba05a8fb3069984831b00c2dfef85ce7b327b932f9500da1f0d7870a4136381ee8ab5f4d9db7427b09308ce385bacd40f7902ef4be5959" },
                { "pl", "4702f91a75e8174f59ef170640d11b73451d2adb4924e54df476d9993e6b2a5ee3ae69b58c2304a5712b3ae2eb6ef68871812e880831b4512c7e5358cd16678e" },
                { "pt-BR", "0a4254ab8cec1a3b74b3ec164043bc741db7d4b641b71b7c1dc48788935f52bda4e558eb08fdbf64fc90edeffc1435c66fdb75ef21e815e9da26698c966a7fb8" },
                { "pt-PT", "4a369911a601b8fee7b834e566ad177f46131cf8214c3734959a59a80a0d42c96749f3a4acad0df603dcbd2b5ada4de0b0a971d6083c3bb0320deb38e7424334" },
                { "rm", "8af44877ae28cb5a38a8c65d6ad4c10e733d3385ab2090444480ba64771f5869b0ae4f66d0af8746e30f2a548fd998382889a8fc57b84066f9c8a163380acb9b" },
                { "ro", "3226b978b4d74d5a7868e5d77fd0d5f4cbfa957b19f4b92b96784620140bc764dcf9edd17620e979602e39c0f5965771f705dd2208ae928df3cdf2e1d0d2aa38" },
                { "ru", "fbb80178cd41db10cc352ec08be7ab84be28d048603c6092599293e444617cd753d963a9bf2d68a1514b96c29272d62fc9fa2c7f7a11d6d40e46db7a372da612" },
                { "si", "a1eb0f7b2f88ab15195544da1cab810a78f4bc8976248eb0ad86f0740af9a8cb5508d8b7d48ca253f068621bc3408ccb276e50b1232fd787efc856dcbac64891" },
                { "sk", "3917fb36d921854e391f964dbd1a0a9a08fa8871a5794c970461714f07a9b033e6599a2b33e7c810a787ca4794599e0a6123eb3d03391ee0ac185d5d8b07176b" },
                { "sl", "a6f78189f2b1333860b1fcbefa5b39bff165991eba3547031bd14e04ab992952248fe48f8a453e0456100edab0b6eef59142623d3706ff76e00f536141d65426" },
                { "son", "593b85e6351b299583317cc92de3bec982839a6439897cb8b4e25617063d4db5a9c9dd4242a1d13db7a330d6ca68deaf433df0459587ee3155de068a0d72e479" },
                { "sq", "23dba670f7ca0af142b9f06919a97d0bee3413229a131f5c8b84e12b6ee85e9a405e2f44f3b96b8710f32e6244b4079a36fb357c407adccd409efa7a13938cf3" },
                { "sr", "75fdc6085dd4e92a4bd72a80d1d1397c2cb07dcec33152caf2d472eb42778de8e0343d99091cf65f22fed2ae2848cbd742ee9221a3bf972e4316f4129676c2bf" },
                { "sv-SE", "991158f8add4488920ab841de59ea9c9147264268a4bfea94a78b0062ec5a734241784345712f913a62fbb89164f14f3812085bd6a0464b368c920025fa88f21" },
                { "ta", "49bbb79da92cd0c18cc192d624a14d3a9bb70110a9c4db263ea1ac3d7ce072041b5337d3ecdfe76cd0d931288793aeaae3d93f08cb594b8007f2556ea487dacc" },
                { "te", "9ec0bdd66c7bb8010b7aff09a016b1ae4f5f9dd0c5673abb90240a477e9dcda1ce35073702f3d97cce96aa3350fd92dbb62f5bfb86181b0dff8bef0efb2529ad" },
                { "th", "ca9819215b632142787282f35c5239c20d1e625bcc97c5061a7fd36e2b4cfc8edd72462d09e9b1290d113eccc9993280fc8d45ceed369b07964973a3d76f7040" },
                { "tl", "bcd1d6963b2353263b1bbb61937a28b9e7602d2661d4ede949f9a02016b1a74e0d140d0fb23472888137d7dd1c609ef188092d6c3fdd6d7fff19e3afe76039a0" },
                { "tr", "da4bc56d6b6bf247554cba1b1176f63f6d83e6e430535b1a22680d1292238e8eea2ed2b9d529a32fecf64e1977d307bf61e8ae25ecdc14b1c54282d014acc48d" },
                { "trs", "547c2dfbd4c28a31e1aa1409182e331ed7298168aa2e1acbef3dac1650d3f9fdcfe34e24981cccf034599426fa362c38de3ad8e9651d5eaa9755a9ffab785a95" },
                { "uk", "68eb014453566e18f6990c6f619d16a5786ee1944eb63f2a629cfa21ed489fa2cade30c682349791e6d50fc3c92fd0ce3aaa869f30f89d125c6b8b34eb92c082" },
                { "ur", "90c1502a1186c1f6eb15bc2bdcd87f277135cc72abe3d676011ec9fa3a994f58e004c3c5095ccb01111815da4cdb6b5a4e66c05675057fc2c1a0ac320d484c1f" },
                { "uz", "fff885a27e8c2df147405fcad4e43dddd12828ecf7bae403d76f8baa4176b56a7518ce430cb7be19cd6b7173d21a5ad630848c466a53e39e00ef1992bc2906aa" },
                { "vi", "bc07c9e96f47ded977468d2b168bfa5136a775f287afd6f527cd9240e58307982da649f8cdffa33cbaad9b47388612c9ecdbdda8c20e7028f35a403c827814ca" },
                { "xh", "0a59ae9bd95ae6270ab5e3b51362e87f0059ebc2102f2b2e900e7eda6b15b2275850831b98ff88bd05981cb8e3f25ceee74284b643d28fa3807cfb937be3d8b9" },
                { "zh-CN", "68e491bda9c85a474a6ced2f85dad366531168e7177a3e6014f8eb8254a17c7e0b09a6a0606929bd7f23cdf3879e4d04c14191fb98f32a64ffc8128732e0d18b" },
                { "zh-TW", "88ef93134f5d5cf30143c07fbdb2a292033a1ef600412aea3673b33c833907e47e3cb0ed45079bbc66ee1467b7b5a29855aa5b3d335751f2284c1c3450b71d3f" }
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
            const string knownVersion = "78.10.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successfull.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
