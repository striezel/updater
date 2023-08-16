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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
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
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.1.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "3c59c29af5d86a0744623135ab72946e209f202450aeb09433288f57463161c7a85a2988665d5b4445110801a310cfdeb3d2de4437ab4a6cff54e2822784438f" },
                { "ar", "8cf42c48a54c6e958480f737c5642d93237ce9133d180aaa4c2fdf370bb82755b5bbb028eed16013d3224e4a003afdd5c72cf9923e45bee05b8a68a4f8bce326" },
                { "ast", "443b91804ec1933448a2e28e5859e94282215b98f7ca60a6e0a8f6dde7c93a035c99c24e7b38dc2db21dfcb2bce9bda2019213963fe8e608b4005545b026dbc3" },
                { "be", "183d45482146595d60a0b7b1ca7060919b05a4ca29ecced067bf52d4c0a98204885fa0859845395651e432c2f41b5b22c282d5e916b6e1371812dbf884a4840f" },
                { "bg", "a7402e451d697238705d3b234b2dd60f95d96e85600e16f1ff83d553f350eb9f1672fd8dd777e1d6a161aadffa749f785a2015560f8afb1bc4bd85902da9af00" },
                { "br", "c5b5b960973d62aa855806bcccb4717ed2379dcd38fe93c9e550f3f02550bdb234d3850de0a4568bcf55c5ed64801021d2d45a09358d17b1061f345c0eefb1b8" },
                { "ca", "94b8b6ee2e2996077179b636360ff8fd1050a05cc4c986aad846bf1aab09dca24f2bd837afc10682fc84646594141b95deb79c13297cff41cf279aa459d45a47" },
                { "cak", "2af43fd31d62eb685a5b3e9dc14dce298aaf4089a362f82ef5b585b1c2645cba07b7d5b4d43fb393cded4bb8ecbbc3ca4beeea078f5eaf54c5bc6a9a8c9e9d76" },
                { "cs", "414abed4878df7002942138ec3f54116a76c08b4b14eef9421f41b248c6af9403a8d3ebbc8333f669e40e0ae58f0041e1a29c772f2cc747b20440d179652340c" },
                { "cy", "8a7487bed3d734a54daf9b8a41d6ecd52a07b2085930191b4f6c42db91e3bf70f739b4ef9b406229b9dc45525f431bd336867b4c5a9eafbbe2f750ab19e667b4" },
                { "da", "7f97d074cb5974a9bc59c13967ad9ad19fb4a106644e98fa384478c3714b9cc7ee21a297c91a7025b7e9a36e56d961174231c63b0bfcc789f3bb05a7cfc002c0" },
                { "de", "ea4c5b112fa24b365bbe61d5a2efa35ac7c6ea6a7341e8a555068d7e96399bdeb9bbea8949ef7ea30c440483cb8fa5c8d371c1fef1553543fbac3bd30024d7cc" },
                { "dsb", "f8863da760a388f5ddbcda6c02351eabd124be15ca054a5da0d15b9191c8c72e915424d0018d54051243faaceee7fa2f36b4cf0c4b98f03edd4e48c2ebc8a72b" },
                { "el", "ce80c8ed419acbbb015bf129fab9d80ab6115d2e574f1d24316411f4a22e0c9388a6c380b7b5e7c3130b4578d76eeae60857f993c4d153564571ded054c82468" },
                { "en-CA", "b439948db67b88473bf0e774f49fc7a15b44c2fbc2f3e2d7a108e456b7527f2b30505d62e7ff1144c61b1c3ac860d47849a4aa15b9fcf17a981fde73a8a3ecdf" },
                { "en-GB", "137edf8fdbf26c848a20c9dbf0d6e107bdeae7099e876e505cb460c74738866d3b5457c1d8ff4f28a8ee35c6e8224704948bd5825e2ea61e203f3621e661e41d" },
                { "en-US", "7e2df17d164a00aba97b5f5f6ba8ef958dcb2d439bb0a45c302f36fb800ed23e28791979b4585f3659a2a9f897a482aa24c784dde2f0ade709fa7463a1b33701" },
                { "es-AR", "17b8f1b4eb4512d089db2f044e9b0ce7a0ea5a4f4a02893808621d5378a20d0b0a2f4f0271ec4f34ac5df55d2d38033af38f6c51381a032a23d2688b4820cb4b" },
                { "es-ES", "51a46404947217ce2fc2e095a3c15c231a15652a0128fd77ecf38542f278d1c91c432d7a933acc56b86eba8640a7e8420457dd4412bbd1ebda3b2dedb80ffb7b" },
                { "es-MX", "dcf1c653f8abcca88768f6b454e8acb3b7553566a455761dd3702ccbedb09e265d7319aa6a30023433702bcdc839dcd3a86a3828c3db88fb6acdae8a008d4147" },
                { "et", "eee0a051628e743c5850d057845adefccfcb3935e83449d0d08e04f4a92d8269be00fc7c8da636581a7ac3c7d87465e4ab467d535bb451c71bb735bfa5469598" },
                { "eu", "cb3241a5c5342c1022691904da2e1f48c93984dc7a41c944ad809251d54e2c512f93e5a4ef9134f2c83b32ef861da54e4b02b71f14325bab2154fbed4612ab2f" },
                { "fi", "0128fd9d4d767c2726db66a478de7615393ece950d78979c44fc174fa95408264b5d027d5af489eafbb23f3f422049c8159ecca8b88b7d02fa64083e7ce0712e" },
                { "fr", "0c3404a4118e6f8471604d9f4e35a1051b9f87c88e2c933627bac69451254b5c2cc9057be4c11798acf690fca8e21091580d01fae54c0e4415ce17d75a99f20b" },
                { "fy-NL", "8efbd50a6b8419edf10665039e8c794c5a6dab2f2d1e0d3f47db646bb6b833565af6c9bccfe52c27d8fc41eeafcf660ac24b9ce7108713e0ae40b891cb475ba2" },
                { "ga-IE", "4a2ebf2cc1c9966b8782d312852fb55ee527fa276f6d647917f1b258b8b996fbb11720573b6aed4de7b58c326b2dc59689946d331ee26e73da298fcff0320452" },
                { "gd", "5190639d42657880a4ef4748b72542f6deed5dd778bf4f2cf91af868764adb68f8a7369eae12b7cc9234c9c10ebd34dff001b58d8e51f5a05960dc9a2dc7f9a1" },
                { "gl", "19709a9172ddfc8830e47142b20c6f7524f1608f18ba54dee0967aeb1036bac33f42bedb4f81bc142609cd09f4e5cd5ed1a726fb4be53ff0f3bdd34251bf2218" },
                { "he", "bd3a98406954ff81127208244a3f158585cb0c39be576bd0c01d38e2435b30abb46c37e7a275b3a43c9b554a5f4104edbfde10e883a5fe85851e585a29d8a2f9" },
                { "hr", "025e8cc0cebf33996d4cb2502846d0a13c623addb6d98e5879120d1276082230f37019fb19651d41b569645f417a98497450db33fbf099b8ffb489e9870c1d6f" },
                { "hsb", "21f793b2c9ba25c4fb8000fed5f94100bc9fbdbb1f7c98b9a81c19497506ccedfaebee0e893300d170132fe3c247d6a36a5739a8a223042c3da9fcea53eac0c6" },
                { "hu", "df19333e253270d1af7e1993620bb78bb7af6464f32920e009203644a5a68ed0466c488161d93f8156d4b1482ff3eed18b96272319261b972a4cb427ccfa5967" },
                { "hy-AM", "29e830c6e4b4d71cc8b8522948e16c313f4950b33e9ff42a36114981f0817c1ede8bf8762416e9b928195d2f5cda26911a904be21040a3e8cd588370b51f7bcc" },
                { "id", "b7309dee31465d99f59c01ef0be09d5e12885887b30ad4bcc8561cdaf7d96d98ff2fa125b050792e28dbe41d0b45d5822d980a4addb0c49f0f55219d571d7815" },
                { "is", "f69786e96a8828f2fe4215592cb144bc5acb8ad8217c0e42341ba60896d6a7eee190a5714f5a876de8b3f6c001296933702b363e34358c515b30f6e169b3e13d" },
                { "it", "9db0245133d6151ec20dca75198f35ae25a2227a96da264be2b357a995804e21e5030bd4866f5ff502e22f24a181475b2fdab135ad1723bfb280df5296f32a6b" },
                { "ja", "f2e9221116be4bcd97cc2f3179c073a4ddb31e2c34522f4790fda453de283b610308672939c6e03e96193b54035a08ff40a5c031976cc2cb9880de2997a822a5" },
                { "ka", "81c978c1ac2e2091827762e58d86652f197dcdc90d17c5b4e261eeb4a56cd41777932821bc428289b6e587d9bfd34ab07ad5a3db26b095c66634c94df80ece63" },
                { "kab", "b45827bc6542fa783bb2d778f05c887a88784ab86b540e75a6cae07848a27c541b1280eb6949d48312405bd6bed71b47cf590ab669fc00f5abdcaa272263b447" },
                { "kk", "c456559aa59b834ff81eb825d74df1e9b4cce251eab9ad38c73d1bd5a3f41acf847c7418fc9d633f1abcdd4ab94c8817155c925e3b96a929fe0282d359a5ace8" },
                { "ko", "5914d91a073ce8f4addfc78b18a3d1f80e1f2a1d220454ebba7cff8e6b6e1a64653af438fe31ff3181719ca03a50ed585a4e15267cfb76c762b781d25c33a423" },
                { "lt", "4f6826429229a7635ee6b3f20cfc88b5bcd8c0f7765ad487d8b01177728a04142679ba02d2b73fc5ce4569dae2ad892bbaf8bfa125d8c0c0954847747ad36a3b" },
                { "lv", "a0e1f044898b24234dae9d9594de06465598c8cb7a30767f11e08e8abe179b0fc2ac07a444291ea981cb65a5df4d4775e3d9c0cacdd983f940a61cab8ea118f2" },
                { "ms", "e4db622c822af361a21f2814d7bdf73902f2e85731a6f35a2f85e5479d12b9e406514e9c4f61adc614edd5aa472cc39c1ade345ee8a1826bf2a8b6a7f43af531" },
                { "nb-NO", "53e2b11ec407b45d50df84b49789299435944be7625041d59378277df1239e3d0f999c8e0029750a8157b37e6ba0aea14e8f8edadf0c655744f30d8bc62360ba" },
                { "nl", "50d46ad93f14237571ee721ac6cb6699b41b3370962c155f0698caa0a9e92bf41ce1ee298edb25f62bccd386d4e29b329fc9a62b972180680ce0e8b147aa1440" },
                { "nn-NO", "7fbaedc7ef9b83d73ac8f0b2516e7996ea841884009d4efef46cef59ce90460da7d8b47b6a17206491b2bf4bd226cbf2714b717ce7adb37de6c89f8440fc013e" },
                { "pa-IN", "6d3ba64d23be7ed021eae082b281c27fc5fb2c64ce40cf9e0e9970ab795d478f08f00c54a16e35f5f84cbc84f0de189a1bb7528d19426e2e4acbe62b003b810a" },
                { "pl", "647757148a439d4027246d82659a229ff3b5ea9c77b17dcd4f79d9a0cba8239f21f01c973c9c23e37da15a4c458aa47e9976b263a9e6f0e56894d5dc45369e26" },
                { "pt-BR", "abe83511d5f78ba8044f3316f9cd89144cc3e6526ad20880a602d7df4b56c030f2a875d464a312542bfc39bbb1bd1ed0b9fabae5734b3800c944cc3e7c6756a5" },
                { "pt-PT", "46be6084d09b074339245de978e217faece5d8b03056c7660da1e6707d030b9542bb3dd0a398119546a76e3594ea94146f0346e4aa5491e4bc0347cd47fd5318" },
                { "rm", "4cc27a08e22a65a64f79bfbdeee4f950de0b8e2af558e858d82b33d770bea01aecbdd50f120e64c37f06422155c4d536800e37b9bd0d47aee9daef564a3e96ad" },
                { "ro", "3c16b03c9d7e86da8a71a683289c5b65aacfdfa6010ff52ee0a814e3cd168d80ef79e6630da76e87029041429e3a3d6789460e6787d0779d2ac212dbdc8df71f" },
                { "ru", "4feefc7c04547a030ba2f9d450624ed345a23451aeaf92336f5c576815a5717b73bc9b00eb4e7f8db5e438f7237ea22a7fdb056e0c5c86fe2c86f3f3b5d714ec" },
                { "sk", "b339cc4053015c341a43c9fca21360f9fd15b9f2e7418fa0c3d7a87adde1bb9fe7681a0ef738f21fff76702389ecdca41798d4edb414eae72788ae85f90ecf2a" },
                { "sl", "44cfa2a3980dec66cadb45514c2d73ca00d657337c520bb45f0057cf8d52d7dcef2ba74156bb1f99beaf756a51a99f11bcc9852f43226dca130433d8eed8c258" },
                { "sq", "ba25a156002901b6dd543d5f83898d3c54263d22b2cbfbdc53703d08133f74363a035e2ba7a70c0e6ec8f5fcd005456b2a62c73aef46f265737a848d2e62f30d" },
                { "sr", "47a5a8cc8f6886f61ca37946b6f86cf22d04d38a139bae596a249a1db390f93716ebdeff9cb181c2d201a53825ca32bb503e603bd0929e96d6d243653a9b07f7" },
                { "sv-SE", "3a433044f5256a3952682658707785a537b659c2a573df9e858aeb35c8481c1480ea8ee45f04a76491ff9efcc96141f02a6ee2b3d097adab85a07eec69a39b20" },
                { "th", "30e3f9e53c30093324da6c9f7b9a639cd66008ab31c5eeca9f97f03bc6e1f296266b4bae02580d0c4dcfada992dd85c4e5717049ca04153237b328b98d9bba0f" },
                { "tr", "0ac4b3f6badb65c16ec3e106dcb7d32ea4548c368f43655e9b71b8c0f0918fb175931adfcd151f78af0f1f5d0f6c910777f7e7fd1c2ddd0488e0f6f85060645d" },
                { "uk", "2360af79512ee713e436566af3014d9e5913b4f37ceee33a25d884ee9785ec08cfe43aef2d253c3c727f0ba9252d578a0f1c32202b6bf060c7ee6d18736d858b" },
                { "uz", "630f4db268cfd3e5272cecb3cee9ed6543c0e951a0b9cd45c36bdc2b6a9d459cfe74bcb4567146b18220318ea037f29b5d6c4a10ff55627b504053b5882f9ff6" },
                { "vi", "895b1658a31cf6c6372c922affd8946782006f0d4be2f3be609a809af20716e0382b19c39d19b5b2d598d42a34770d08b5752286c0606e1dc265b673ae8b6549" },
                { "zh-CN", "adb8beb216ac7e22e76122841392424e1569ae92981cb10537efa12d22d68c2c93837af90a5e8b4ecc7715e4a9fefbb14cbc5b15d88928c9e0b7613a4710833e" },
                { "zh-TW", "327673b7f203916d6af15c8bfed0f4e95d93a3fc5cdbdab8cd2e9f5d3ad04d93ba0004a39faf0cb49b446c6980c92a5b8455aabda3bd9a83e7a1540df1a35984" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.1.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "aaa303b71892a8c463f634b8bee6c2d7ca67f68fb08fa96cce0e06ddddec495526d5e72eb904abdaa08b01e01e89c73457a2c421a114b56365ffb3c4c3481a4c" },
                { "ar", "b99d4aa875ad2b10b2af7fba8d4acafe3c621c63cd7560cd0ad1cc446baba65f675063f98586dd42f8ae6f162b7bd917eefbf3900cd964d0d2786c89fbd4a880" },
                { "ast", "99aeb8b620636f6688a17888b81072b4d3cd9484bd75ea2870839558e3595c19b452844a48e0dccb44cd76f4018bda4a3c01b8b6865d3380d8608e81f570c444" },
                { "be", "1aba3dcabb39092c27718987696add3c3fc067ee71f56397cb9983d44a9a87f1d34779e7df81ece62f72f870888cfcd6d99811196fa10753896188ea82d63a30" },
                { "bg", "633ad760cc0d0797f17a2cf478040631d587cfe2c395f0caae860727655bc7155ecc5ee5b2f3c23bdc4e41c0a2b5f389f17edded384f65a87dd5458d51f57878" },
                { "br", "3c69dc9ad79ca1c28a78704a8577bb3fac86f85a93937427a5b2b31105f0459067284f8c12ff0cc8c124fe450c35c5b32ee0b41915def89a64606c03e0cd0193" },
                { "ca", "1c0f3504b237f64d7ea981d75ecb91140e3accdb1b0e67c65c571278cd2791f3cfdc9cb08fb3b15f45dd6cd1f311289eb5057768907c40a7d9abd70017f50a09" },
                { "cak", "35f6397e4b4dc52b60d8e6ef38ce7913bab35b5fd51ce543c6e297c7833e17ee1b1bbc09c5ffd5b98ffa0c0114f76830996f9af11e6fbe27590431afb4371679" },
                { "cs", "c5a92083942e433896e69c97b291c75f68e54272c2235908f44b14f2f1dc22dbf23b2cf9ef9fb68f8bac26a6335d3fa33a18a15131767c3b8618216135928653" },
                { "cy", "7f0ce466e1bfc27e24c84f90d01495ebdf356654544b8ebd5898e102261b958a2bcc5ccc9ee7154937597bf84e6e4588e2d82220f31142f43ee86ef361349405" },
                { "da", "ad503843f6039ecd21e40e9dd21614062700cc0a26411f2e957c42df05135bb3ebc74dd45c82ebb9ecc96c27d8e4d5fcf9bd617b25a255b37e30dd7532b2541b" },
                { "de", "f4a7ddf12155f2d72fdcd1873e395e5a50e5cccc83bd091657c324d257fef3c6dfd3b54b2aed7f5c6ca6538872a467858aaefea5b26056392422ccb2cd5542b6" },
                { "dsb", "f10563fda5ea9264cb07832263d0c6f046a398a310e73d4cec027364f39515f48f1f4f89602431a77c6239bd278f4bb8720603889473cd2d70f2c1401ed169b5" },
                { "el", "e62309777b87217b81ef080d2356fcd5cceb925b092486e86e5fa5705ebf4b4b75b707f20309ba59c78cce455a4ca9bdf07f4e006265bee387f934ca3ba8d4ab" },
                { "en-CA", "cb98958bb755a986d1764b578d6cc0cd88c23c3990a6506b6c165ae7f5b7e4fcb8dd7141eabcb5ba63e15a0a3d44eea622157493b92b6ff6ecd5933dea289f96" },
                { "en-GB", "3d1888bcedc8c9db07a68b32526a1350cdc9b70a0783ffd3944e0f6ebd4a2326534f8c6b06d1afea7e1467677d1e4cdd2d82ca9281ad5b1c5588ccba4cc0405d" },
                { "en-US", "40e7202ac97a92e0d6348186821c0813f8845116b3874328b0360f5308a11c8ec25788f52535e80d197a639bd3baea6c0e1ff7253db2636d0f7a1780d4dc6efe" },
                { "es-AR", "283d188cdd7ef7ef744e89ea2c143843a42b4960cc30d27b0ff618bd09865d713e99aca21abcbf4d9722ca1b1fd3c91a7e64019dba828163be96b9d593ea376d" },
                { "es-ES", "863b5782f7bea6e757538009f56ec4ac0f422446605961069da2f46a13d38edb6402f859df06794c71420724ab5abee7be01d104ecf316b635926e655eac7f87" },
                { "es-MX", "84a1bf0f92619e72db2e2316e28a4b3e5e0349b5151d76259d126ac5c52a3dd4fbdc904b02ba53911c7b42eebcded20e165a64979f56b778c9fce884412b6300" },
                { "et", "cdb392b96af9c7e70da55f139db8cd531b83ce4057b9896b04be77a0a839831009103c8b7e5835059f30a0eb405698cc355741867c90fb450a6c47cbef9f4a3b" },
                { "eu", "8c2603039d3ca116906f61699c3208b3aa5f011aab0b7f6f39e726cedcc381ee6717e5932873f684db0c5a6c9d122b39c64fa9fd3f8ce2a4defdd609d0b2c554" },
                { "fi", "4ed6570e93cde11f6f8ceb0125fc1f3381376026dd900fd3abf49da0848bf7f4dd43734480e677200c03540989dae1430d375d06f512e725f130e9a5eade36e0" },
                { "fr", "a4f77af2e814825bb030a97afb3979ee67526522d4934155bc22df49731b4cc4407571331f484a236d6b20a7ddae6d571070b592d7a2d3841163735b7c92dccc" },
                { "fy-NL", "bb60905315834b586dd63fb6877da98c5e0cb93cd64e658a23d3b2fc985746181c85d6c091ea5146a1e02246122f0cd18d2a702c9c9d5690bff3deb26043e41f" },
                { "ga-IE", "1f1656cced028c47b76eecdce019a89a023633140a1c50b3920f17cd3767b92a2a98b10ea069606e44a1819ec2ba1aa3ef53d72e0e1c7e1b2b58f9c576b27121" },
                { "gd", "9879d9f798b90301fd911b7662e77de77a9fd4439977f7a583966d7c8219378f115bc725d6fcaf089fb800309da3c08ed95de7e173ceed678fd9d31c836ce9d9" },
                { "gl", "ea1308af6e8b7bfb4be8a3fbf8279f6e3dcbadfa4ba5f23e1bbb21da68a67ea0195eac505d437fd4c6f9488b8c3584a6431e95a5b93d2fe5a52c5f2256a10c6d" },
                { "he", "87494757270f5e2edf21efb1cb2e571b7c8f666fcb563ac3215ec70e8261586bea818a93814343a013d1c77f941f8a30aa316056f4f52f099ec08b6e1d4e33a2" },
                { "hr", "7fbbf01cf66db66f53749357a64366f05630c00de0bb323922ce8d63d737721007bf9609cbd2cc0c0533dcc5e8a9fcbe0a455b0c78dad85548de7385054e55f3" },
                { "hsb", "f69c94067ba836edc3a264946cdf553dbd2aa3766bfeb11476b7a739c6ffc41f7b5367f765439ab60fc15bb74904b7eca79375f88ef18d7ad7cc1f105838c18a" },
                { "hu", "3fbbcdc01bb9a9199979ae50bebd9d16749d762d20b34a42b8ccb0710615492b608884fc13690c511af1c3cf81e66cb194216f2546c968fd5d8ea51c4b72ecdc" },
                { "hy-AM", "01803208d3dfd054225383d0f6a3f7283671687ab0100d8c3fe6b8f7798a5ef075584c82ab42c72f94336d327b17460e9d355c64e440ed3ee5fcf8252f891af0" },
                { "id", "b8fa121ca1ecb4f9e1bb242a4b79617f3ecb1306af11bd1f686d9173366f207fb1475ff04b39575d6820c75a14509fcc94cf71f2cbd85cc2a51dfa4e1c249492" },
                { "is", "42367cff47a6591eea1c8963fc1699b44ecb40a4fd1821a4d4c085a7662c041626f3eebd9c9bb9ccc01195c793b5180aa2046bea7bb448bef84b7100c2d8d36f" },
                { "it", "ce7b59cdcd84fa6c216e549cffc76ba31264a0766d2eb84b6227ae80e8faaa8f95e306e11f84e511b915dea40960fb954614b834649f4b43c77364eb7ffcf0e2" },
                { "ja", "f9f9adcb47b2b6e63dabcc72ec33bb5595040f0b33cc82dfe7eef3db8b9e23776b96599f5bc7eb304880a1223ce0f4b1486cb68bf2621924021473c81eb16856" },
                { "ka", "e5f8bd5fac4f3e66570b114ae83ca3814c39412c96bb0393e11ad0eed0ddebe8ab631c6b2d48d268e6b34ba2c1bbce9ea61699ec821b385c30fbaad86e400155" },
                { "kab", "316ceeac629efba40232396cf78af0652894d1cd7852ac4166419552f03a80d3309c4c8f6c0d999bf565f7ffe3799d5d2623de38363c0f3db268932cc100dd72" },
                { "kk", "6b274a39062886576876737db8309fe30742976fad530b4bca89f4aba3a1c191022340160803166093c8941e22ac6c7cc3e437469bab6496ba064afd314b8e35" },
                { "ko", "55c458c3d0eb2ca88c172cec6c6f60a34fceecd3c9a3a48938686cebbd8ae6c527d9b637bcf11a5c1ebb7f656f483e96a2f7abf55f1ab32dce6de06649f32813" },
                { "lt", "d2d4f6ee16ef8b83bb141206c7139fb6d3c95dda35b9d4b1ed40cc58754e49eb59b409470b054527f1249961b7d7a51c8a3434c548c32ffd0fb820d210679a55" },
                { "lv", "a906f7421fd70f6dd3861d00d56db8453bb201f7b0702be5360c2004c171e0cd92d58f3bd96f3097047c10b7e91c78c1b2f2844eb026156ee9fb7678989cb3f0" },
                { "ms", "0ab51b3150cec47994b73256a67dc1157aa24d06eb19a7c97555775e3bd05e762e6ebeffcf2661596ddecff1fd096952daeb2c88ce638c565a83048702b8bf08" },
                { "nb-NO", "d97bbf2bcc7f8aa76e58e20ceb069c952ac9552ed9a224cd1d32600114297c634b204ccae465c1dc157ef0a9fbef1d7d7f5f01172eddd2305265e12d8d30dadb" },
                { "nl", "27a3d37dddc57a56c01eca403c9b4f3cbc59630620787e697c321b031a82dda9a6280d9c25b14849036621668a87214d04327bf87dfd3781de48042195289373" },
                { "nn-NO", "5695cc9600b5962d569f0fd4e8e7bb66905035b0c9fc0ab843b9dbad156f1c7df443215037e21c790e32808520456a4210449c0f843062a2a54330545b3cc459" },
                { "pa-IN", "b03ce0a673f83168e7744b3b2b8950ac314dcb7ac9a85932034d062982207d8bd3c83bec7d03dcd605cf355b19365ae2128752ab5a68348bd06e678d22218962" },
                { "pl", "5f4790416fa422b303fd958cb191f3c9fbaf8804f03a28a94ca5b825f002c909740ea6645f2b3c1a690ecd6b8a1929fa9b2279cfb65343a4f9dde74e78974a5d" },
                { "pt-BR", "f4335485a8b58adcbc58cb78ce756b36e422a51bff149aa350f4ed2d51176289a37c7b23da6e1216e6f385c473ffb167736e325990c73c7049af656a4c15fceb" },
                { "pt-PT", "032aef27d543b5df4db011aa90bbbea9ac8f340cca7aad3ff8d43df137097e8fe7cf9562081e3f0fd9cac9ebf206917263b25de502893ce1bc1330bb1692dda9" },
                { "rm", "8d9f8d5882d94c9682946557780f14c428e53fd0dbbc98336c3117ebacfef47d36aea3cd146696a56c74f25c10dff8067ea1114273ee0c6a5a39c992efa405cd" },
                { "ro", "552a2d2204410b9c95d839405db8570f51e9a75f289b0b5bbd82c942c5b263c495025f6fb10e5fe455e72f5799ea17adf745d6f447a16e1f44eeab3758b8a231" },
                { "ru", "52d942a50586f756f4956d0a2bde364a4f67e7891866a0afbd10485ee10f11ad7c52a397ef3c5412e4e2b2b324a749ebc9f14b1c53f92b508176fbfad328023d" },
                { "sk", "fd9753533620a7c28469db77e14c26f6bc264110ba16af716e9d37c7361fb79d025420b53f52b32d4cd67662c7f9d264c80e9f301be10eb07e69bd98f0d9cc19" },
                { "sl", "5bf4e862e0b15c4541d9e75b1141d161e7228c2737fb604ae37baf5bb5f25f489cb3410db82546933b581cd0adf299c0effe919c3101e9255776c41177f603a4" },
                { "sq", "451e8b8b9cccad78baa89da3d5f2e85fd5294c1e1538dd843524d63ad793d1adac097d54d8324ff287869acfd573e291c2d362d324361776666ab1768235961b" },
                { "sr", "18cc946b9fb0b8cf84b0fc7d1b18d3244892bb75fb54d3f3a2c3431606cd09c9bbf7ae6b5b9b63de81b13526b495ed4f72e105cb602b3dc821e84136767c0051" },
                { "sv-SE", "738d624568017f84e560a95b6250ffdab8d66e73202ef87c6d0128060ce601688eaf8e2664e273c530eb1997e54784a5a08997567b4a119f0ea2567ca70fbe43" },
                { "th", "fb0540f84f26ae0c084ff79d4fcc134a941bdd1a60336089280f6232fea2d356f485f54a9dfdba889e75ff58725a79109e939548409740b788ecb6d34f66c6d7" },
                { "tr", "3d4dd30fadef1feb7339e72d5203efc43ff498667c0971ec90815f5dc5bdaf29653c19a9e8f7c50f59ae5e2f241ef99fd998c78a677330debd11b6caccab25e7" },
                { "uk", "68fc38e71d4ced696d66a59d45040257e8e48a20ac1a1c7988c2c21f2456d84ee8aad142cf6192e631ae3d7d64ffd99f2ffe682e1319d3ab092836e0c0f9a683" },
                { "uz", "6a3772a9a6571fdb7c6d28273edf8b551e00768b778f36de6c1d84c7f81ac45cf4ce58c086f81453c22a0c66ff2b4a9ab33d6c46cd1c2bf2ef517f8a2b88ef0a" },
                { "vi", "25d04e3e0a9a85b917337b2394f94305463aaea2bde7de62ade344fe239f95ec86d2a044c509c2d6d6fa89f478753a71970c551b8f9b3fbff78840a2e17e1a6a" },
                { "zh-CN", "3c776d2a0bd4a0cb38bc9823b16a6652407ff6f827a07ff7bd7e3717b253e88c6f76b6e078249b91f8797d26230d4969c53960994e67312903dd5ebd05f66238" },
                { "zh-TW", "b9c57bf59ae190c7a726a3c3cded9d44de81cfe09a55580fd6fceca3e09dea0622be58027441cdbca5dd25a638ade2dd72655acc53d65bb5ba1908025743f97f" }
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
            const string version = "115.1.1";
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
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
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
