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
        private const string knownVersion = "153.5.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/153.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "92eb16fd833040a9b50cbb95b5e80a7157d33de0b2b837b4b4c743cbb41a1b8f5c72a707fefae7835cd770e50d91937bcfcb0aa9449b5b548acb00350163fcb9" },
                { "af", "b7dc19ee384659748028d66ba13f5d2872207503f25a43f19b23ba48ef098810dd9433ae3d2ecb79080ff4b61adf325351058fa34a5d6af2aea16c4c729c7e75" },
                { "an", "b8b5868a5edb94d4a470a3e99aacd29a00abfe2ac09547df21d111a7549caca632fc880dcb0ef1d29e008c296335230087862d645835451876adeb469b3657b3" },
                { "ar", "ac0fd3adb4f4c472e95572bce22b6ce85aaf77d820666e39d2a8a05d661c9eb4537cf284aed47c88c85d925da033dcc3e257b775ea7ebc803a6be8afc6f981fb" },
                { "ast", "30d91ab62181075d44a0c7d1fe6471b1a18eec80364a2137dcf08abc32fd23bb31fd84a03f46730708f2e6abce549d8221dcc5c5063a6c153e10ec7d06f1c363" },
                { "az", "aeeb1c72f11536714d8bae93b49302c894f71041dce2323a0238d3f9a811a00b5236ce961c75a21e926a8c1d2bb74174bd6e3afd7645c283f1e92612f13cfbca" },
                { "be", "e38f41315dcc60afe74a84f23cfaaecd648cea63dc0243149a46482035c04d249abf3381be0e38ed2a614866abe12e9b485e985f6c4bbe4676aa368f58613661" },
                { "bg", "1d964cb2938ea68fe831e738a2bd13967fe77ae1ad8a1357a267b27d3397a5799ea2c18e9fd11bbecb9821aa00f9ffff1d30d9ea7b5de577066a62e0238258c2" },
                { "bn", "96a0a9b4e7d1385706508f5c61e49a76a339a2401f7052ea00d68fb608c1046bd99bb46f6479cefce54d6b0ed35ac9780025b41fbf99caa7078e3314ff53db89" },
                { "br", "f97def99c8e5844317a7da469c17619fae8e5a609df7c66fb76bbcaad50aaf5c6c4af3bdedab54ed711ff85ea303f014630ef3959b9e55d7e8eec1298bc352a4" },
                { "bs", "df56a786ed8a15ad100dee49720d7c52c7de9676f32889c284918a8342e8606436691c7aa975a8e0dd1c358a10c0c36e27c37cb224b88a3ecf8ba4ea72a9ce8a" },
                { "ca", "113d508ff45c4e75a3e3781b4ac365cae3ff495d66034117ab07859466885e519a5e689a7ed930ef39f025acbace8a174df859e44b70028ff260c90b1ea49ee1" },
                { "cak", "4dd900b0002561e556e48ce9cf65c1a8a9688cf94beb5360321a75fae4c364399b91f42be9e9d4257e7f48f4bd2b7b42fcb4a86fcd166ba95231ba31055df74d" },
                { "cs", "b69a9717ae39fec7c523db4929f44204cfbd07f1a48384da0556b55ef9388c2e4221da9725c1d4d9ceffa6856f225a99e24bbc8dd92a93ddf7268e6b30bb0315" },
                { "cy", "00bdef2eca389a1bedc913c69af33c0972962e05d12cf85c4ae2d8d65cfc34f641fcbabdd4aaf5dc802ddb84ce1666654ad1f7eeca539d8e843721bb1b111cdc" },
                { "da", "43037df15099cf0a2fc5a4c61abbb04404b33b6b581f9dd92b214203915d96d72d8a12ae81798c26017f3647034908f1a251894a09a272ed295f6a94325fbeed" },
                { "de", "885dcafba1c91ca9de9ea60b061c4692eeb68e9f19ca12fe5a238ebe37800f964d562710e7dc427da5f8349ae408ad1e0d837ce48ddc5c2dbc213521b22dcf78" },
                { "dsb", "9958f25c0e64ca30f1cebf52eea010d3cef634c154da73ba7635f7f7968a03ec45d53e3b46949e73177838c08a8b02bbd30cc7240a8f4fb81d672b5d2e0c4531" },
                { "el", "b46fe5c4f68cd72297def4e1c6c14290f0674b691f794891f4ba793552437f0036dfc80170c290a6565ea72a14739cc1353799b8a728e72a78c82f1e91a93a81" },
                { "en-CA", "3ca228e5d32484a422024f7ae288e108ed4b1d174b2a751b271e626c22b5a8ae7b31e78d9f6d09be660d40ce97b04d942aed4904c1c196fcfbaae59ebb841cb6" },
                { "en-GB", "04ad6fb12ace7c445f9cd9b21323c3861ef90adc4895b992b3c4c82193b9d9cb429b351021de0782259fbc1f5ddc3eed8e5d208958be3c8ad775cdf7d4af7116" },
                { "en-US", "f2ce6d90f29ffa54db74990edcdfcbab8a55bac1a154f014f1181d3a8503c915c908732f6425b442374ae575d2616fbf9b9e0ddeeed406c513d09e1650727f28" },
                { "eo", "5fd43254f2ff06502732cc93185584ea893c305d33cd3496576533d33cc22bda90cc4d61eca8a9d38a5ca341643e8054a61229ef5615c07e22cd031734fe58ab" },
                { "es-AR", "40dc856f21976588972c940bb450b361671740cebea70b9b8de632afd91d82e1132dfab43909952df694ee3096e9d470f0ce77fc600455e38d7326d98e1a8a83" },
                { "es-CL", "1cdf6d7ad17e6d1f633d1cf23e9962ce79fdb32a0b4e10bfd9f81b8545e7d031778c7dc2848bb69999b37de90ad66d08418f8f98b324659ec34182aa94f9b09e" },
                { "es-ES", "041925fbdaddf8a00c17f622da1864779b964c7827c6e06971ddfc04948bfa50febce8eaf6b9423bfe435a2a27c0a88df175d41a17aefdf5756ed680a1aad68d" },
                { "es-MX", "2692cb0015c109c70ada436a9d91600a404bb7278e24c07ddc0c221f5b64a51f312472fb34ca7835aa697fd23133cd74fac45f9c786ee18bae103b11bd529abf" },
                { "et", "f1424cecdee2284ef4e4fe3faff38259a594b74f18b3b0017cff7b07a4e52c01579192ce3275e909ea80124bfaf80a9bb1c3fcbcd97e8e688d73f9c60604669b" },
                { "eu", "d1092871caa500752e073f9d0cbfb96203ae32591a3ff8ee2ba5d193603c4e6a8e112c4c11a461dd7752854138f61f22e2ed79f65d2e1f185bcbbdde1330630e" },
                { "fa", "5bc6deca535348ed4e444657d8fcf819bc63c43136d979003ed67e32a4cf846d08163685c9697fa434801329675d43173b3bd768a46a9a8215fa13bf83a2c3f2" },
                { "ff", "022bbb6340775c730273aa0f8df937679589d99f4cdbbc39bc34273ae7f867b8249f19b7bb432ce0b2c79d296f6fce05351efdb09aa1cfe217afd114bb51d9f5" },
                { "fi", "40659500cdaeb1c799cf0298861200cc4fd248b1d0eac6e831c1c769378024269d50a74120839fda58d2b78657a7f7c2d3f48ffc6e2ad54ad8136b844497c163" },
                { "fr", "2ed351fbd4d89abcc4743f87201bff6987b696d5d73e7206deb9359951bfb2930b946383b46efaec1aae1d310b5c2ec8e2a48e67f9a838872730792ad3a41aff" },
                { "fur", "85376f892aa21d4a676ea08fc6b5c767b88a13eb711459087d02e48776eee826017e331b3a7d480f3da9a1cb0bf8fed8154e0e791962842a593af4d287d36c78" },
                { "fy-NL", "8e6e2bebc13f9b075e3ae29a87c9c095a017aea1d0075e7b78d8c66ba4a004b88e9b07a0b55a496d0bcfb1dc96ee036eb75cfabd1075dbe18e21d4c09f0016f1" },
                { "ga-IE", "eff5d7981e7b0ae969702c77003d2662a31dc4e3ce815eeeaa526cf1a8e602fafb7563b7aa0b5a23dfc55f3ba203225adeee94c225330f27c9774b5cc1da6f63" },
                { "gd", "8f81f2ad0e90165735f2761fd42df4dec5c4f86d4f1c812369a1add1a9c46ddc9d5ad14f74e0ded2d323ad015f1eeb789307ebdf4aabf8cef52273e3e27b6e7f" },
                { "gl", "6c46bd89d14b2bbd9325a8aea10489bf9ca05abf5ad1bb9940d54834c7a1d05ac5e37feeb33ca77c83a810b6494590dd345710ecdc3931e55c77361b235176a2" },
                { "gn", "985ee5955d76ff5341623bd106a62f8c238942bcd9ea11a685a79fd1165f1081d385a608420f09da9bc88425bf1853c2cc7c685eb3827a7767965fac624faaaf" },
                { "gu-IN", "707e0ffe2c9b44f5b8fba1dbe487dbb7c14ebe41d8608a988a6aa3e8b817f85eb63ae9e9d493dfe8f337d16f4027ed5417c34357a5a3223c2087767f5351a587" },
                { "he", "e4317f90b4dbfd2b9e3d881c35c61fddfccea9990d2cad0add32f91324561245b08e1dd03ff23f98126a32d0334a32424723926d7e1b2b4bf809f9fcae9d3d20" },
                { "hi-IN", "5f3fc35dfe5eb3c1c5f7b5a32c92b6bbec617792f20c705c26091d6173b5780556fc2c0e5068a34bb22f8b00281cd3320f648ed9a5e6a3ef62d3f5b98f1ca7d5" },
                { "hr", "d6802e817fbf12bcd28e60544f239d74fa1b4d143c43c8da36753eee67638629c344699104355daede15244a290324a7cef47bac7379c60c8e33b46a5cecd783" },
                { "hsb", "82c20c1c5bbc5fd371103ab4d70512dc1b2d08d5962cb9bf2814861c836537ca744fe512e49bad3fe82ade56404c656b4f81f897ff81a545c9334b1441fc1d9d" },
                { "hu", "448cbe38e5b4c10baa948ba1b9013b4d490e3316b73e8954ba8d81720b10eefbeab0e8f3549dcf6c8867afc471c7a2a86bae647a93c83249e446608833dfc679" },
                { "hy-AM", "f5d06f128a8e22bbb054c768f5a2da6f4341d381fe833a5c97e8cd649f2e8c631da23e485ae8f1ea93439d892ca6b2e6cfdb776f4712cb97f5247c490dab9a9d" },
                { "ia", "1bd1bca9793dfa2da0ae9e213110a03c3dc266802cd5d5e575be36ee4a19a9592419920de85184e02d7e5b6cc7dde7075c4177dfbb503b379421c25cd207a0a7" },
                { "id", "ba93a46f2e7a8c9f07c5b1116a5f9bfadb521dfd05d3c2925a080abd62e64dcdadc740e804be0b57e9eed1588ebfcbdedec18df4b45e333744840733c8352dfc" },
                { "is", "a3cd3a5391861893239c465ca294b7d2fd7438d3d77529535c6c37db1c8d0cfa405743bb983c2f821189333ca3896c5d8011c4b6baace12e5f370b078893ef34" },
                { "it", "562bdcf923e562bbd0db7ac324a89bdf7b1ae1530a0d1ba9be4befd1a99355a21ab68a0aacbdc17d9ea2ff9df39c8ce71a61327b214d2b1439be0fdf50dfed8a" },
                { "ja", "a72a14c2d68458a290ae8ad170c9868c622621fcdbf4f1ad5da082436d0174c574d47c24c1dbef89ac62ff1ce1975a920f7caaa378facbee319f763603f57584" },
                { "ka", "24be66ee0d51941fa3cc6aed762ea0ee6d0067caf3dc79405166e6688f49b6d5671aa0e705fde31b8a0ab109907880d8f7f0be8de80b1663e00593424bbf225e" },
                { "kab", "344b01629c52bdc31a0504051a65d18e1c3f8715a3eaee26ee011b5c2b686c235f9eed30be2e1b28de35a190fedc1d5825bcc6c236f3d0e874467d830881df0c" },
                { "kk", "d39e6baf511ba745f0ca3511acf3625dac20ca822f329c092743b1ab76629cc68a7ddec6f059b4c3b5dc72f79b85dc3605d968c03063279154303c14fe93cfc9" },
                { "km", "3b8a28066a5e1acd9e6e55de595aea96248742ddd9ed10c06ff9e07a209f3caa2814bee279aacccb3522bd0add2c876d03e64d49d225c8e3738606829fcab504" },
                { "kn", "08ef20b3ea5d94d09cc69bc595602672daa5c5f109081fbb5b04fd38f53b01f048919e334466ee9c5c90aa405293882c4ca336a8b286fb3e4c4ee2a4037904df" },
                { "ko", "7ec54ad6f5b732149030bf674881826a857601c4f53a7cec0d84b4e9888a8acbacc4e2781150ab092f9cfc1bab05f86a8beb27938298f32c06078f955fda93f7" },
                { "lij", "52799088fcf5064f6808211277924df2e450c66da3c261cd578d011a5fc7dbb236ed2ab5be16d3a91f80558e14891d79fe34afdad73495d42ab77143049d4eed" },
                { "lt", "458d2b79a876600eb5d06b05050384805599b74c8683c7bd5804c0f1a79514437540bbbf8a75e972821cf024b49eafa2bc6043c7e77dc1d2968c688460ff4e1a" },
                { "lv", "9b15847b8e99b3129f270e6c485094eb210f51f4e6bb9c0e32f3737b967bc8ca74b747144178163657dd1f7f247e466310be4897cea91d82c909f46746267cd3" },
                { "mk", "828068a13269c85cb15eade0ff1dca8459d60983b10ae32fa5aa5bc2e20cf3f5032c17b9454d50203e8e29b2d3fb3e74d9a816d6aa93887ec19175c81067139f" },
                { "mr", "ab9b628367e08406235d7e730c86400c50c40bc2f06e592674c36478b4c944dacebc8aa7e8388416aa615930ebe9399a37eede4ddb84a7a6e24ccb06246fdb0e" },
                { "ms", "0c7082cdf38ed41eda8caf709754704e5988c9184f7302f89246412c0d4a7492f8efa27a6ac5d2738ee47d2b2915b0f1106b3fb52824e53aa18f5971749c9788" },
                { "my", "92dde247828e8615a313017f70351d02ba95c73d61c6801405f72c890d07b866d8ad8c765d91d3456554e9778d41ccd5448e496db45b0ccf8f85a8b1ee70439a" },
                { "nb-NO", "47bb841b888e764380df9ebf7f622b9098c84c128a9fdb4e9ead8e947de4e4f13675c454cd3a39a94625b505e1498430fe9008e4b0ffdc2e14edc97f4371faf7" },
                { "ne-NP", "3cfdc655a4bff2f3824a7310e61865ca701e4799646cb7c661c41e55353559ec9eaca4cccc05371a7bdff52090248e103135ce6e2075caa7efbd416ad80d9145" },
                { "nl", "f5b9229d763f7f1b71b68f6459395d8ae78c9aade4bd39f3bdb27d7711d6b106b5b928f89da7374dfac66762f0bb6cf366e19c26282ec8c8c5142dab31c7eb19" },
                { "nn-NO", "ece2b4bb0558c5a320da1541e16b58b8ef1e85114658160b52532bacafe1da870fca517285a623f174ab47cabad99cb03cb09f592435d65edeb0c2d9c4922331" },
                { "oc", "712560f877393f29b199dc290d45f681f106788beef1bdfed0c626f47c60c40ad705c183cab5a99558f2bfd2ac9e7ef95d6b195782e3b66fc8eaf34d664d5cdf" },
                { "pa-IN", "32904ce1ed6ad6d866be5dbeb0071c4f60b631222f38c04d6cb6d33caa21374ed3c43d63303c655915eee5f76838e3c241f313fcb911191013e480e77dd7134c" },
                { "pl", "028ae54a912d93773912cd1c8b165678f8f3aeb499448ae741affcfaf81547f237526b2e59c9b3e92106832ee22732d65eb25e388130b3646766dd1fd9b01d6b" },
                { "pt-BR", "42c20715c72e7f139ee7a1a091d17d34a6bf33ed21c62bed654c8967cf66ad37adc318c823f9e3170d841e6af0a1f19e6387ba86c3f5d6bc04dde1a91871322b" },
                { "pt-PT", "1b1fe831ffd433dd79f629ea42a41b7b7a043a77875787105f34af7e123f460af5233c516de539f5237d34aa2aeee3b1001cc2775bcc22b69304a9300ac18df3" },
                { "rm", "69241eea68dc403297809ec46eeeefcee609680f42639578100334056f37623ce679e282cd4c36d723b7a817257903a0818bce2334bb2ec9ccd8da5cec141161" },
                { "ro", "3af46b60815b06eb2de6386a6c1a296797ae398cb1b0c580a35b714c0bb9d5dfa34a59f101d763c0ecaa419cc00515a0cfe1b66a944946239b7ffa8e317b050b" },
                { "ru", "4471ef0f670adc2f8d9ade6dcf010e29956ccc8b3a8dafee23b6d2f9a28bcfba5d7f7a670226d0dec4de4091d36f516debdd22522c6d0f3a5005a043cc43093f" },
                { "sat", "c9e762e8835cafbedfa5cf6a3c74f9404038c5d94dbda16c10f9cba12eb82badbac2f1f987af7f022423472f986a7b8fa6b11beaa3b0e558469c93ff5da5ba36" },
                { "sc", "29f60a7fd858f9dbd6df28599372b68c29474b81ec48c2d82f0046c42d0bc007f2861ae0149ea0d3fcda8830dec1bd3de5c4ad2c8eb8d186cd3749604e6875be" },
                { "sco", "06fb288a0c485c656003b349f237a12b03aafb5e4a069292a52bb18c3c3af8710732478152878503e6c747b47b13b61baf1c2872df2ac4a49f1acf6d034b1055" },
                { "si", "94cdd346dcd167e86f6148dfe7ecb65a5cf77a6d84fce9b7550db63de5a0548b45eb9dfc7a5d12dfcd31afe00e197a752501ebf2cbcd824d25d19d8251039951" },
                { "sk", "ff8c55cf0d4fb11de4b4c25a5c95b20b733e44eea6fa23c373bad23b294709105bd710aac9f588e40023b3dae3f04a71d5250e14cdc0cf5e8e68223e94b03f7e" },
                { "skr", "f974fdc7270099958ed52620ff7c0678531a51be16016ba49ba2aa36442398badb71581f1802d399392302a62dc79823dd22386513ffdd6d83f1c0d879989ad0" },
                { "sl", "2ba9223fc5c493a2ef93e4a783c3cbb126d7457ae84e7c785da8e78d1afdec930dce17a06f6f44b0218bf8294afd8ff7d311d8375375feeb90208931a447b2aa" },
                { "son", "d26b9fb07ad789796a3a396f4de865f1c749034cb568e1e4509e8488ac8dcd0b58bccb19d2d4b8aacf3f42a5dddcb65f50a562c01fb83e9e0797a15e00436d62" },
                { "sq", "b5cfb1ea82730777b4815a05c5719f210b6307888f313bea6ea24656ff3a0edeb6d4b67db8e63cc5b7d0abcd50584d5a86e661407e3eae7768b8d4b0fc76ee9f" },
                { "sr", "ec1e4d5d414ca6193b5f37bf0f6ef7f331cb5470a17d4657d366398c87b9534a78d09e9ef8633cc15d8666d8a0942f0ca5dfc6e534e5788e007bc62240feddbf" },
                { "sv-SE", "3b1c0898936cc60b238c1da209ddf663e7e83eddd4a2fc9e2ce0a5330f294203acd25a0c3b3d06b706858262921243e380279050a7ed74c9dbfe1a86fae9df13" },
                { "szl", "24d8e543826ffefa80d5b16b0ca9851cec3bd680494b842c86fa00023ddda1756d8d892efe8540aac8d822ff70bf21e3c3325b70c54c8fb62b36f68ef58f144e" },
                { "ta", "12d61bf14da6589bfd6109c76483fb576ec410a80eb8ab4fb997344dd2bb0d6f76839202505e14f836b9ceae8ba68e5189610fb4fd5f19d983d4fbe3d475562d" },
                { "te", "e37d926c028ea76e1acab67fc4b87254bb04f48110aca53dd45a60fdfab171ba244f0dab0ac94f93ad1ffa13327037c4a1cad138c2e9698967a9efeedb46ebb5" },
                { "tg", "47c6a32a2387d52b5749b76a63a5b84a93d521eff72a76e0e22a57f46615b30f48eebc17192b081f2a4f1ebb47d40bd8039e93aef7d27b5f730811860a4f2fa3" },
                { "th", "11dd397fd34e65a46646ee5cfa51ba3e1036856227c74bd17fa12e5245a0534b8cc7acfd00ebdd942084a77f91a1d44665c100ec4aee02b021bc6234d92b3b62" },
                { "tl", "7381f8645af4b28b385c6de2a0f2088b5da7d8e85deff2f7e0a1eea30811a509c41250e7a72806a22dc4881babb5a20ffa73a00b58b47b8c0aa2392fbc133995" },
                { "tr", "a6eb365ecf2078bb1e71710f1a2a192b86749f419d711116402108c6808b27208560c60ed3f650d08edc829fdbaea6453053322124889bb5cfa8820c57b9ba54" },
                { "trs", "04c73e171e44dcfe4292dbcaf2a41c0f903bae90904c12f4d3c8d8ecbd5e442f8f2e5e5763d6228b03816ea51b370a33f88c5c8fd856c0e2336d8212894be6b2" },
                { "uk", "2250c9ea06ee5f6375c444ec885e8854f11b04b31aefd547a84627e2dbc706d3b506a1c0a1d56656cd48b14a93e80bd6b00a90e111eebf38ab2ad1217438c6e7" },
                { "ur", "0dfaf50972e6879de9614c3bcf76e6b93894d5f424185922d59d2fc88cb8d7e6f8ddb4be897341d0fb2be11bea27aee6565e3ff3abbf7ccc9df2c759df5e36c7" },
                { "uz", "f29fa80df29e5e5163c55670e9d90506084ad1b2ee3854d1e03cba7807ae4611a11d9945d9761946fce4244a32be7cba50affc9cbf9d44a3614dacaf02316bb0" },
                { "vi", "be7fcbebe4eb017cb016c2d19217d68d801b7487fbebe68aba47f56992ee64a8ff7d36820f435879263b82e5e91a72773fc2320f14c1db9a149fa460dca4f5e2" },
                { "xh", "5926c0483bfea2c3c3cc92923ed4a45919946a3fe4a26057751f5369aa2f93e3ff3ef093066790177acaa0a49daf99a8eaf6abf8c54d78115b7a91d93d083b89" },
                { "zh-CN", "163a994ff0fbaa9fd69861ae37c3b0db1fe83da759283e55a61ce9d6be04d962f19b83dff297770838bdaf989ec4d7bea8c9ab821dd3d1374af442a84b190b84" },
                { "zh-TW", "cfc9cc3fad91d10e54e8ce6d8e096a31478e10f776404f156f7891db467d679ee3be2b545992c74397e5d2f3becf19e65b261964c72e32d2f6b7f69060df660e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4dd93a9c49c4551662c1dbaadfef1a6779ce3444c48798d54718b7194e9a8ac1cbbd8dd71b737de260f3b70a7b2d4a600bce8f8587e814f91e24633dad6b8d7d" },
                { "af", "6ee58dbe787fede0ddaf3e9e0638f47a2b4ab1dca85c51b41fa4416da1a5e56bfc43debd44a3c58e4fcc2875fe3751543776aa9ae97cbb65f20129077d9d0fef" },
                { "an", "500be96603d96305d9701afece1ecbd93ab2ac441bcbe496040aedd2ba0554712540e44823b0c0dd4baefc742bf8001ec7f8b41594064384b3fc537d61fd23d5" },
                { "ar", "0bbf525a65739fce7199af95ab35addfb4b98abe39b3318d11b726586df3c7d4dcd8f5ceb805c4cef51b2c0bac66224c4e9cd4b20a1ebd878125922dfdd7840a" },
                { "ast", "928b647ecde2609e5347a36a40125708520e054e1141a7b122b384a536f4b1543de344490db088dc227cd4e819cb205ab40af56ae71a4fc0e35c364b2d20d6c2" },
                { "az", "b16d4901b78d1d9eaffe2c8cde976ced3d96bf427c24e8dade7c87f1a5f30f2c18bde874335bb6ca68b55990b398031512b932f0b612f41eb97a3f59854f517f" },
                { "be", "9015c002205e1277594b27eef6ae9850c9a5524c7eb694691a1e3ae32955daf7b7764e31bdc533e82df2f090409d0a26e6837500022a7e0b0476ceea4a56a004" },
                { "bg", "c4b9e678633cbda7a7380e43aa631bc37ef540e6683e14e2904686cabd7a9680e0f386dbaefc4dab2670ab88a73cee805106015f9f5d966377f452fa7b4298ee" },
                { "bn", "95e83c2e6a907f40321157d7d5a789450d245652744210ae7d30852e8ae0cb733948da0c48168bb0ea32ace0949cd784027ddde61bd4682b1beb848f40f6f48b" },
                { "br", "49c66fa8e836cd840ed8dbcf5c3149a2a977c6b6430353eb346c3e44ff2bf33c893821033c635d971b9d47d8af6eba614529bfe5c47be00bca2a203438d2a185" },
                { "bs", "05134947b4a05b139dabcd76249624e2b377a4ac37edb990322c78ce3da7e3846bbaefebdcc9e1f06e0281f212d618ce7901443ee3b015335557380f765a44e8" },
                { "ca", "d6b4d1082bacb2096b5474a5cfacffb9790247b1c853fe854c3c20b25f37df4f93dc338e1470316222c04b64eed68ce227678e5bb278b939b393fa597b22d0a8" },
                { "cak", "a57f2f66b06b53b3e901f7a6b727714e3dfbc53e17016b107a7cd563099100fccc5b46c302a62c65e59e1112e9386643e1e6dc7264ee6bc7c41f8f8726c3373e" },
                { "cs", "6c0771a9b9a56c37b54aad03b4cfa75675f4ecafc4e58b2ecdee73e99f6d35a14bdc576f2a1073b4d50ea0d370ceb5807a83429bbeb54413a911fb335beb848e" },
                { "cy", "99eca80c495dfdad4fe677b4624bfc9f61140db9d903c802d9786d02fc1f1062c0cdd504165cb97206c872bb867b7191c4e8fff8eb00ab06cb0743543c8bc173" },
                { "da", "85fa5e8db81467cc3e4718a1f1ed47a3030834b050f567ef322a51a80faa7949a5d4feffbf220c78a7bc07678df5b6d9942b7de11ff68b67a3be6efa4cb76336" },
                { "de", "310434034a6d0ea4fe2e4c97f590c7002ad26c660cfc9e2d30d4d5b482e2cd8a872934abff3e64d4f73d7ecc8488832b7db888bf73f77915372399b23a294007" },
                { "dsb", "e1608369e73ae8da08f331f7fd09ec6c5ad5aa1ddf3aba1c3c9a45aec4918c79a8e511902ea316c95c28fd53ac6245d4e7c28beb2517f7790e324d45fef1d3d5" },
                { "el", "082dd5261e44481f4091563c6cddc2b80992f21c8d5dd1f7737a440092fddce2841217b9836689691bd4a8f676b22ea09c9506350ba05b904cde683b228bcbec" },
                { "en-CA", "48dd07063513ad6f8ffdd2d01ae0e1f212ccfb9299d8698280ac10f005f717ffc845606d4cde29c6deed5889b639ddb0b9c9b08a4c9f36d1df391ae2ab5a5374" },
                { "en-GB", "f799535ad6128647805c2f22acf243966138d780021685ae57dbaae61d0660fa046864feeee4d2c1596744a738470e10fecb1bdea2a37aa13fa5df7a5fc76443" },
                { "en-US", "a21e0ddb2862b12ba9d8245cf4e9e6840eb64c1d966829f6a639c9ce725627f5329b17550d8b4e6c2f3457938d67ae71a22651edde3cce23c1988a77e09bb84c" },
                { "eo", "9c78284fd656b319960b975058f616c930823fbe95fc68043d3b80f03dd786f083e9fc7bbb74e13d8f99652f254c53ade129a6792c654e825ff3b450ddb92088" },
                { "es-AR", "8cfd66f37a7d37b0691b68d71fe63b579abdf1bb46f4d890e770dc689a47ffe68fc386b2bf93648bc1b5f6880f7c29a63eb991c2cd33841fb552d7f1ea925ae9" },
                { "es-CL", "005bb306d6f2067250bbf546fa9b712e2d81a5efe35f9a6da456412f9da5106b56d547d82366c9d8e1703632b2c1df03f53187d60abcd499167861888db2d7d7" },
                { "es-ES", "74bfc85678538ef8f099d066124e496be781145da87352c05a68d962e99dce7d41d99096350feebcddc5b71b560e65a379c7f088aae69dbe70456d482226c3de" },
                { "es-MX", "85ca6cd9f9e379b4b79789696396a4582596ddab1c225f86bf5988fc970b87d6b7dde63fb7de4a784fe8fbd56d370811655ac3a2090d6af1e152a79facdd6d6c" },
                { "et", "9eb1f437b907d58431f133fdccb5c994c1b79c57ac3c7c15cd935e64d04c63635b0707375e4e677760138b7cbf7cef6450d5b622a31d9d40e56461f6dbbe0613" },
                { "eu", "a2ac3f0510ca8f277ba459e816c4f32671f3d105ac536d3a7b9253cd6a106666df1568e6e850c7116ad6b3cbb31e8d33cdfb675d8ce17fa4f3bae17fd0a12b93" },
                { "fa", "5dd2368b82d315b1482ff133c712327d37292d4d5e54898d17ba7185d6407fa907c55b92e85fd7b69449ddd10f3a30ae36d77cd7307dc3723d038f308a861a8a" },
                { "ff", "c777b2ea58335707bc5aa2195afdd6033edf12f1233c0ce3d287673ae9e5f50e06c79e6362449b59509408a3733774706b803fcb5c9311b6406152b272cefe26" },
                { "fi", "48cc48a742dc51ef692bf481fa5c8986a233d2cc2a374c3287c832c57173caa1c61b36be683430aab1b9a50eb39437c89f46f5e54f7563dc762dea413c76ddd8" },
                { "fr", "28e87a3f1f50e7d354594351fcb0599b14439aad4fbdae661990572284e68bd2b7bf92df1d84b4d0be2f454ee3e8544479a2affd912cf7ed6f3a0100c4ad5190" },
                { "fur", "81f7fea3f1cda6e6d78375db0e9f82df65622e4ae3b0c6b6586e58bdf0862fb1dae214fdcf6bdbdbe2d7ae43d31559648ec0d95daa97f8a6f9ffcaab9e7d9a78" },
                { "fy-NL", "ea500604bc95e68fbfcd5dd3d40b0b10620d83cb6125290cd0c56657db9d1873e077679a797c41d7b5f21b536873dfa4d47567df47a1c72af8576386db78d9cb" },
                { "ga-IE", "f7b1d4f157c7baa460382c78df3aba06f9fb92b0b5cee63a5b8246426909869b961ed820f6ed8e310424b08dde9ddd7e69dd09cde6304873771babe29c220433" },
                { "gd", "bbd9af67b8b914d309a1c7821c9b1370500b300e576e9b998f4669d44fe83512a239398ca65aa41a2af058d333d75049ae4ada58ff453df0dd2fb157201a5ada" },
                { "gl", "ca5458ad1e22f6be642d85c24b8c2b711760dc005d72194e3abcddc187c967c7bc198586534ad2055f730193b3c77f214872e5b1fc05784f22a4da37b686dc76" },
                { "gn", "60a9dc15b4c2820acf8c2fdb38498e65cbd6e74a7231a8d672d43685f9812c9ba5eeb05b61c7a883556a24d6ec1c682f775e5131e98ecf8901ab429e080297a0" },
                { "gu-IN", "404d9324721fe2d1a431c1faac11ec0d282a1e4efd66a5539f30f6c33cb6193a2ee086d9ff267e4639560b0919924083ebd8df597724a38e18910fb986df98b3" },
                { "he", "03a7d6db2ecf80c7d1676494c09582e577492083d4669c894b96c3efd467e2bec52fc5a2dd45596777e7813790146bb4d0ed5d2f3e7b5c5a1f1b49714a5e3b7a" },
                { "hi-IN", "9a4c9b55d9912a0e9a8cf6c613a83bd88854b10344d49a606366ee6516ba5ffafa0dcb364c324e92c3815ac12e4a61112847120d966c779f1060ed998d0ab298" },
                { "hr", "3eb24d334dcf8f27cd798da629f6307d9da563be2ae592a8ed45e40502a67308b3dc08754cdf28370c10683650685da274001266ac44437147f125f2907ecb95" },
                { "hsb", "cf45cf7e821eba0bba1ca709b215632a69bb5cc4f006287a98735771474ce0f4226baa6e389e6039189b670ad17930e1f062d65642a19fdcd8457b66cf95885d" },
                { "hu", "0f744bf630fc779756b2c3744d4eb78ccd001eb52581db38cb31c30f67fad95bc77db2f8cfd419b50f5a0cae478358d67050acf68304ff93f18b5369f5927b57" },
                { "hy-AM", "efd4a1af61bbd039e542bdd834f651de2d2719d75bbd085851b548da2e276683378715e15b8eb6f875a33a156b86e62974f5ead8ea131604d05082c999c5ccd0" },
                { "ia", "a46ba702b91d406fc4bab32f78bd9cb2e4bd7e3b6ce0eee8d5947fe737eb1f792aedde9e3c901795de25c4dd64397cec6cb9e605130e1f368e7fbe0710dbccac" },
                { "id", "34bb62d05dfa183ce743372b1c6dd5450c9d8d38b6db1522f26dad9b32062bf90f3c1b618039cdc70d9d914563fe2a669bf2de548f8ece6855d0ab762424990c" },
                { "is", "7dba69387400baf3f87e4395dd93fe87021356d50b385dc6efe4e1472a81af6e383610ec43ec4529d193eba6bcd4d9b9a43a28559b47669dda4d9f8ff89dd003" },
                { "it", "fdadc9f5392a06138205cc18af9bd5a2470ecd4bdd3758c8ea138cc51375014d4edfe2d88b3da6a821539d27b8a792ada5dce512f7b47942c42ce749e74dcbee" },
                { "ja", "25b7db0e292b3cbb92707a150d1fa679cec2f0963493ebceebac5d7463a1ef0975eff2a0dd1e5405e061c084fac1b2ca31146534c8bee4a55e554f8c5a0e7b37" },
                { "ka", "ddd5b017aade3297533749b1e1e711fec7c7d477a0e8603e78ee94dea1d203b78f8ce6e4b264a9b77a202d877320f669dce9662630468273d26009c20cb8bffe" },
                { "kab", "f9d3222fca879aba2f096fd0445e89122b6ba39b0e365ca7ad51f9ed74018b1666a01c48d300773a0afed8e895b4d37ff6a02605651b5f8cf10f5df4c8f1212e" },
                { "kk", "9ed983a14281c920927033e1cd705b415ba5da1261b8d2ee686776ba9ef0a7c1cb653a29d452a07cd76c09f1e0ddfebf14cbbfc8fa9699e65f81f67a370177e9" },
                { "km", "dd860810fdcef15ba940aeb4110b0a577c6c6b01049fd13366136f2791b8e06eca7e4049e309fdfc53d875469d144c9fb73b970e533ddf4953f21a0282305244" },
                { "kn", "65dba5334bf65c21bed5fcdb7346668f0dfe08f7cdba3832e8f1d382aa244e21d9c430c267ed682c4f9e87e6a6e933cefb42bfaeb3267e7394d371f55a7581b5" },
                { "ko", "5b64fc4a6ac9ab36528b8634024d7c4d54cd76a39e60a4216a25a66ef51f99f74ddcd9b9931a2c74ff19e8e9ab88e3eea24a5904b55fcf7e68c572cff80109a8" },
                { "lij", "7cc0695a65430bf5b65e0f997a2ac3766c2e00808080e3f3077c76953d5563fe6c9b8bb190ed0e335f3387703e04ead1e8783c1fe4718c13a136396dc06135bb" },
                { "lt", "5c36596e01496e8d2dbc71d28cb1562090e25fb762443811dc8cfc46c9089f526a8a77f36bba66730713fa7f4e038b9ea68947e4de08b3586b31b94e77b7b011" },
                { "lv", "ba75332ed58923b53937d74e36b6f58ce5ba91cae911317092102515c0cba49739a51da64d6519b214a858aacd102217477792dabe12bcd8500c36dcb7fec7c4" },
                { "mk", "e0bc230bd729285dc39df90a77f24bdcf841496540f8c48b02550934aff94a1dd0bcd643a068f81ea725e07658491023d56b0b2263e6579174f528f283ab85c1" },
                { "mr", "5e309485f04f11653ac4089a81b21dcd6c02cf037a0cd7d5042e94610fa7a55f939f710975220ae31a84d9f2394a35cfd104859e447fcb38f9b7ff13a2a7683f" },
                { "ms", "4b360c5e9db97529dfb8049781fec040280ac973b0206100354bd2010b9988cf5cb626ac946ec5846d5719613c2966a988058d68eca2fb9bda1c1e4cc1343325" },
                { "my", "aac4860e6148af65e44b26ef817ddf4468d825dcb0bd927b6216f215ca448fe861368fd2643dd242483e386337d087c9024050976a03059e44dc8ffe18fd21b8" },
                { "nb-NO", "47054449969765d3edfcea26233fe33e77b7b479a9d3ed6ea23e856258003e8e9873af54f89b3bce3a83fa591d468ee2de55b00b9b0b5e116a99c30d02abbf01" },
                { "ne-NP", "a3bdd2c0577d900f267e166993414598463aed484f6b9e8606f1717a82b063ecc1a92f989213d92dc435f3f1ef8b89d22444b3370eb7e426a4bc0561c05c24ba" },
                { "nl", "57b873797a0226fdd591a7b058a3647d68f7c6d740d2fcdb40bc9ff81b5492480dec952bdce8594ecc9df5777d8369db088ae38376a2897c5242d930416c59f4" },
                { "nn-NO", "b7a67b7ebbaaa138fcb07495cbbfa7ce60d20ee1d7b405463612ec425ca664d0d93083adfc7dbe788179d675fc51fae1e2b4cf4a56efca0b3bbb804979f82463" },
                { "oc", "70e411bfb71b7efa2b2f40ba81ab6586fffe99997c58000a7155c0d9c12449ca43534469805058bd9fd154cb1a14d5af56af1a1143cc6fb37937528cca28258b" },
                { "pa-IN", "186f83ddbc807d2dcea0429b375ab4d00e8d905d54cd51e5751e16cc50d2fa243873305267e7d4cb8835d9b04073c5e56a01b7f8e1de9d73b50711b206025b2a" },
                { "pl", "77f6150a7ecc8bb48e215521a0ff4ad6d9ed5c0d80d8c5d024b0463d9680c5cab940f9a337f3f4acb9df40422deec09b94d4ffd11d167e443f98db0c13a8d2df" },
                { "pt-BR", "c8c811b9020e385e745985f1992b2e0787260459533d230983de34f26cf47015addcb3e184083102a9b8c589ac3e54f208325e87b46d6f2b0af22e23f4f706cf" },
                { "pt-PT", "be41e5bbbd06e71a9ae4ea4d2f1efed56446f5435c99b6e11a58689da95a4ead4aa8afbc1c24db1c46fc18228c1215d6301d595b1a0b149ce7da12578bc68e25" },
                { "rm", "aa51bd4de7b5a6a630b017f3076a8e14f5369a438ad2c1a887dbcb18fec2c864437c480a4b6aaa05cf2cf64bba075a7dc8808598bbbd24acc31b2ca71720b74e" },
                { "ro", "0db6e42a2ea6da74639ce5c7398ae950ef61296ad59e5735bb35e9574df2c84051831cb285bd98b0f11019e8cd2d9b35f60cc3770acaa08e0411d030ade05916" },
                { "ru", "24bb9c175b8917e32acec7ce2e13929fc3e89cc81a6ffd0d2b299f4ed1baaf4bee2e7d326e18c2062b7d064402b6e2d66d52eceeecbddfb10003b6f2d41f1ee3" },
                { "sat", "f3ee132109621ce6fce396e175f0f8ba8d5057088acec96ae19d4de0aa651e9f51e99fd2896100639b4841990c47010dfc4db0c810e329d0208a81a97e830545" },
                { "sc", "1d1060f0ce6ba8a54a3f7320902d877526b9fc071abdda3e9b26c796a8c8cfed1db93824a303cc2c6ffb0789fa986d4af84e2040c949a80662b9a34494b43481" },
                { "sco", "a22b1aaaf65d9e0dc94c3cf8dfd4859a54aca640879a07752698c7345c2e129bb341d0401dfb3fa942a5cb6805775358dc6069e011821887da1e3afcec460091" },
                { "si", "3b1682b5c9308ca39c5ef256d3df349f4b2c7d8a73a850edba5bc6a976c03468324532c82d05aacf1d8a49c0573bd1b1b583b3674c596cbe931ec770485af54d" },
                { "sk", "adcc81664ccb6351732983b0f70523828f7d181dc2a80fc1c516b67161e2dd997cb0723c0b96ef01a3307883a272b7e86b8eb7f7992f4c379d5cd03dfcb77141" },
                { "skr", "873028c83f3e68a637c14aa758eae983f39593dbd1e748a4dd9ac3a612aade412b005f7270feb5fadc51fb7f7bcc0c88ded664bd0f389b3bf8af18a0f83f3c1e" },
                { "sl", "43bcad63248825cb26cf86eb81380fddba0f97a9bf364fd544a3d87290c04583112bed02dbecce170d86b789ec65e4c3f6448565ceb79fcc393551dfcc82b9ab" },
                { "son", "4443291ccf19c8059cd93243603e96feeceab1b1519e62ae412188b9f68b4f9b84d0f57dd3ec7fc8ad0c9434659bc462c06e7c438a20af65c5bb0f72a526f13c" },
                { "sq", "bbf304f381089a03dbb03633d41a2d14a59a11da7d2a2ec769437d0212c1ec2ef14ef3465a0f340e90a1b72d1b580408c35594e6461bf649702b523bfbe00ead" },
                { "sr", "1f24c08d4f67852eeae300484722bc6dc57612d9e184eb3c1e03a25cfa8455b3c87f0eca23570405efbd6cf1eb0ffc9814bac7f551500d6ed471144659b27014" },
                { "sv-SE", "63a233de1fc0e725dc3214d3236feadae4e151a64a7e8cc15c6e26ee2433c7b8029851bee90b4a7b5171bf250a08a452fa9aaccef066878395a7a2cf1cb1451f" },
                { "szl", "e1228db28d24eac24e6e47ef7e52618781be7adb1822da90fe18696aefcfba756456eb3ffd4f453c1267f3355f5c28da833fab505a050f9e157ff5993daa262d" },
                { "ta", "8a6f446525485a6243bdd3876a3e9c042d876737cc465e7ab861e54d8f42db4ce2d75829941ad60a0785c08f1145689b522c5ae33be8b609ffc443deab879521" },
                { "te", "d614e2b82f280b0020144d21b68ba908f5822e2412b0ae6b53a60a1cadc3bd7d034d32a9991f9a522a98a3954862bb28ece5635d0c0486c1763b354469b9c74e" },
                { "tg", "57afe0b98c9570cab0e01b281973caab73fc49f5dcd957f7086c9cd5006bb399df3c67ce9548e64cc70a4bbcb97a12be5057e3176eb85275c9181c3f8f20cdb6" },
                { "th", "e8f0cd54566efa66a0bc22bcba4dab2fff28f493397153d3258dc203738441b242d20488627055900dcf69cd25de99b066409dfb759de1ce7e32924a89c2a0f1" },
                { "tl", "23195c44e56927031129fca69eb2a653e51bf4ac7a7c4e24cb61ccbf4f48e28b9dce5390ecfba6d585aea59019ede5387af1b707d998ba903897eb6b3069f04b" },
                { "tr", "829821258c2aed7558d6ee9e6f824f9eb4f6b4c907f44bda2e48d39fe2cd907e85974cec90acd8112fb71e8e0550e0b696be9c003cb894cf242d0662bb1754e7" },
                { "trs", "f10b9b64cf9808fd6881046c27a0ce18a18965f60cea486ca43a0fa4fd6838eb2bdcc76c35d7c8ff19754a439bd9201950f3610031fd5be5ca1282ffc7536ea1" },
                { "uk", "d30597774d9434b86217078c7d404928305701d2f72d9c5fe671b67de497a302286180844fdff918a1b17e60b23767c1eba4eea1e56acb8319f871af9014a35d" },
                { "ur", "304fc231255fc8837db53d60cf5f07039d8c738e323909f1a2483695af4c13553b6d98de2dc2f48cdcae819910c99dcc08bfde32cc6efe80aa503b92c97d1307" },
                { "uz", "42bda228048b92cfc5512d576e457046b8c0bb401c389a73e53aa5bd35b0f24445f806a305e9d3834e9b285af796fe46bf57eab97c3e223cf7ba100d530d4198" },
                { "vi", "208be3e19124633553b5a31cc57e2f8e8678af72de7c30ce32cab135cf212693af9b90036a4674d54e15eda249a522683f25c992a662e288963e11ae63a3dee1" },
                { "xh", "563d7c0c69f2f42d0f1072c90e6c32507db2b4c703045848ec23968dd69a2dd2c8ea71683002076aba0962b10537e60c3b22c226873a4c69681b067926866592" },
                { "zh-CN", "958f405826b6aa8884c5ca32f78e919994479279c4ba8d904406e969c47e1193fb137e5e9e8f6b2aa6295b4ca6f7a3040e4e6c9a4e0dbca569af1620b8ffafb0" },
                { "zh-TW", "f70ab6e121f4e67fd5e65bf65c368642a61b8e7cb4a361cb8cd9517ba56b1af887602acd615fe7abf2a9a4cc7e0cb100395d735aa4a38cda2bcc6b4baf1ae1ac" }
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
