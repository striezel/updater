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
using System.Linq;
using System.Net;
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
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "89.0b2";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/89.0b2/SHA512SUMS
            return new Dictionary<string, string>(96)
            {
                { "ach", "34d1194abeb4916e00cd9413135ae46d4e565c5965e61a8d1ebf7e7ff9969f7858834002514779ced0b72abbd2dd3feac580eb5bcde60b4869a19c915fbec62f" },
                { "af", "29b86ca89caaf2fdc47b40e8a95773249740897a45c3b8f343a6dd94ba65cad812788c4c3abd187ff4ee3be1fc881421124d0226a54bd186234185d21bb40009" },
                { "an", "a20d3eb0ce97ff47a5a0adc0cb8a2e8751856fa1c4d43b39b5f3593883d30afc5205f3471bb1ecb81919528128e3ccf14f4cd123eaeada044bcaed8ce6f057b6" },
                { "ar", "1f8c02ceeb9e113bd1058134860d63e6811229cfde7b84451008a03ea7e9719a04bbb27a22596b6ae698cef61b24dc86c624b6953816197b0dda7a3b1e95faed" },
                { "ast", "0cffb3b7e8611efd648ade402fe1fd69f7577799444e99b81ffd3931ffaefd803c2f679fc18c0d2abcbac2a605df80842647869abc1af785896dacf6bf74e4a2" },
                { "az", "97f59f43e20cffd22579e1ee5d9fbc76aa1d516faf4d5b6e858bd1d51ad768a3230543071ee471b9b5649739e671bb0ee00c415a10613ee82f9e55dea366ab54" },
                { "be", "e3d0887ffcc2730030a8cfe7d148bb13b0ced1cc19d7f73fefafd3fb2a13e44ccc949839b1381d9306ac5660e500e93fa0c8ed6eaa23986319f3d06679b155a4" },
                { "bg", "66cb1a10e7b6e9cdfccb77c8b3ec02ef177b5e1fbdfb789f0dff6eac0f072eb15684cd711d0e0bbfb0f8d660b4e47305b161f9b64f4e6ef26cba8cca66c66d17" },
                { "bn", "ec89dd895256fd3dc49edd42aa82a8658b623a6586774478ae8f42dbd062e8ec5bcffc8313d6dd7a1e940cdc81bc44a04254224806e7c146c8cb532f83664787" },
                { "br", "0d274165f6c5cc35d5d1f929aa6d429b507b284f1633e46daf378e6882eb7c1c135dbd836453790be53091e6c83fdc07b49c5d6e23b324e9aa5c586842faac88" },
                { "bs", "f6a9a0bc6f665c90f61444f7fdbf97e9addae7ca5c52cacff768583398fff31dc1e3d8df8e4966aa0b03d9001cd2bccd8150e3724d231f5cd0e19db3ac0cbbb7" },
                { "ca", "ccf367238b24505a9a5e4c6e3e788b9d3fb60d1dcbd6407b4b5f6479a1a85d89bbef57cf3ea5b236b4314a2314db0f1ec80a250e732f8afbc8d47cff978748d7" },
                { "cak", "4ff9a30f35b5549f4730db060b052d40f9fc81b2b3bbbaf168124115408d579e270113858cb230c3d6c3dbcf0b03282dbf577eb054aeca964182e88542156f9d" },
                { "cs", "d470e75ea6209cad035d06772af4bfc566ecb7f47c8c586fb62f9ea2d10e128b37f2cdc6b4e210272721ff5fefbb62a090fffc7a5c5acae756a8ec91b6829c50" },
                { "cy", "39920584fc358b53f91c2efa564d4a4fc65981f895d46aa4ef65e6cc14747695b4e1df9c6c8d4d117234ec785d14a88983d3f0d2955b667feec305f2a3566a5c" },
                { "da", "5e01f527a3fb55007f59c33e3d4412668321a547b5f811c76125813f6d01c3a7317dac279e99748911b5996f24c9390271d26015b9132c6412aee824ee3fecfe" },
                { "de", "afc14251405fca63a2c3c74b0dfc0e5acb7d834b21e778162ba5dba2b6f3aab6afde47ed6800b3773d097640c5e54c208236cdc134e999a45a373f0d3143b6ee" },
                { "dsb", "b3ae5ee8ee67b9df746f16f69cc09d0d02b3c30bfb58b26090019e4e2dea56d2f7677de6a38712f567c8ab309b9c0d7ce35fff023faef463e96adc86cb5f48b8" },
                { "el", "de77cf3830571947f8f4dcec26abc53efee035d639875dc789c5975c81a81703c2f1dc1849c08bfd3c7fbd27bea93b73d758ba4f0fa99d1a6372834f81ea61fb" },
                { "en-CA", "e03ea6b8b634f774816d385f079f3b0a4201fa1a4024eff4315b6e93831796f7d83a6951a7f8368aa0660b9caba432c3b29bafd2dc2979e87d0fd106018305bb" },
                { "en-GB", "f7d8d7efae2c0659d80e105e902b2991fc9fa50cfe37e80d7d9b4730b8106a03596dbd2c8df9939b022ab94b54b84176b379326a1717c37b3220d314c9710bb9" },
                { "en-US", "0abde0d35730f6983e274f99d4c36e5307f0b1794444261b8f9739a3522efe033e3c87b11181e8250102614376872e2c20759ea41e9c767a078c2f92bfa5de6b" },
                { "eo", "b723493775511dee2cb53ab62e32f5c5caab20cf87ecaabc825c58413f842dcc5f1470d012c1dfb7b96b86aee2c98898a1f548c9238805d0e419baec408198cc" },
                { "es-AR", "e0ff31f3f412f923c6f58505a18c8619e5974016daef96afa5751b3978c6994486ed07bfbd73c07000e517d4ba5055ccbacd3f68e2f45f5a76634e8b1c4ad609" },
                { "es-CL", "4d7c0a0b10bab8e9669015c017e5a02e07718aff7adaba14909f5b26d5951ebb811f734699db6a8940d17c3c8c1ef31f21c92bb9ae3f090f3d5ef46807c5a5cc" },
                { "es-ES", "6d1b60c49d71910ad7fa348a29379eb102d4be490c18971158e6dc8caad0aff55bc0bf2785638a4ae67516d4534899fdee5cd75f6a041cea0cc98460caee89c8" },
                { "es-MX", "f23d386be74918ca4b0e17eeee8bdd4838240d7a9ddb4e846e6d50013f4ff82fb198fbad6298eba3dfa22d6580d36f624736d460635a1aadb488cf1ff2915ef0" },
                { "et", "c87f56be039b55715f8a49bc324114555ae2a46a790d43f062f0612b20a5c75269dc0bdcd94d1b8a7c4a327f817110c47c44ad42ff9cdb9666933c133d9c5487" },
                { "eu", "41b0b55daaa46da52b1fda68f891f4a0877a2f3d95037f5d0fe1298a65077bdbe3c4d078e914f6610b35e2306d61d1d620e74e25f0b5f6bbb3f6ebfc505829e7" },
                { "fa", "0068c0e1eb10a2bae6b63c75e130115168117ccc0438a01cfc52d1221673b277c2378174bbdfe8d3e0e299460afb35fd8fc55a3ea03da694c386f1d01716c633" },
                { "ff", "354b9cab3d0dc20dc93928fdc11be2380b5bace0e6e7d0e179d349272fdab1a7b83daa4ce8aca92afd7b6856c0372beed3179c549bfe3adb0a7042110570d0ab" },
                { "fi", "fa38f31d2b8a09f5e81873c73d36947be3299c05ecb022727ecfac259541643daee0188fafed741268756c4c41e27a0ed66eacbdeeef2e6cd3dfe422c2ca04d6" },
                { "fr", "1cd8bbf115e1035c7322a67023480ef9606ce424781536e9540b5a292878338ab40136536fdc2a2fe4a624101bee621ce11cd76a272c5c16d4318af537dd9df2" },
                { "fy-NL", "89ec35d4b26ff490a42559126e8151c90f4b0b55cff6aeace0ec0b09bfbde960b37e270f99b4579a7d24b0561c5e2593b29af213f70a03925947cdc236b73b4b" },
                { "ga-IE", "9294ba9351ab8dec48d08cf18e789f540cc8d7d7e62a3a0c5beb42228c6a3af0f6d3f575180dec72827c53a61dd50dd8c28979f36da9242b295769ed78236868" },
                { "gd", "0e7d33790300d2a0c4376b274730fe81f039d4b6d2c771914198ae33e61b30b1266b72eeb87fb92c319f119c3e11efd42319915381149b1130b646f4194bead4" },
                { "gl", "a564bf7666d6250071cb8651e4fe3742a72f43a61d839c607862512610e1711bc1a3e6ca4a5a4f7e572a3823e00b3d15d6efd3696659359467463bf0eb8ce74a" },
                { "gn", "bb6cc76bee7103a0d5fc65520bbd396f97e10d993146691fdcb3816d076107eabc7ef7a6023f87f62e718091928dd6360f33b5925da84a81f5a205bcdcdb3ca8" },
                { "gu-IN", "791435685526f7889866aa7e75ff50a58c725d9b2ccd0c9996b5e8bcb36d9f1da9914a8e8fc854e6337fa911e22b422c469d30c1ca9eac9ba258a0b6ff8d2a4d" },
                { "he", "7264d3b12be65baac91ed3803b7b911dd3fcfcaf3f8fa84b2593ea6789fff5be16975ebe12e1f124289f1974400da7281883c61d67b2843d6a064364af931ed8" },
                { "hi-IN", "84e732fc054261a6f131684dc9babc0ca76dbec53429ba5d78ca739cba16b3b2d262ac3fac983875550f01ceb07ec4771cf0b06123a4e47beef8d8af6864cf48" },
                { "hr", "9a3bfde950bd3fba62155e26fdf73e23dd734d44734bd433d5119994fafc9329b26ee4bc699381885c96068f816969d81dbf9256210740af4cb59fdae528ce75" },
                { "hsb", "9a697bf4c3c8612f33bf8e94e16ed300bdaca1e1ed0d7daedf7ff19e98e3a6b405085392bf8d894240eea19a52f6b6256942203454a88ddea3b7f25b9c8fa954" },
                { "hu", "e9407e194b0ec97fd173faf494b267ceeaeb73c9c34720953adc3088bdf4552d3dec6725a983d8ee781f0dd785eaf65edf88798fb49cbb66bef0f6358bac7034" },
                { "hy-AM", "3ffee97dde008bc4ac0b3650601fc87dd80a407e8f7fd8a83f833c1ff4278932546c81f459d327c58ff0ce0f180b1cebe735c9a1555ef732809e471fc5c0505c" },
                { "ia", "e00c9e87298d4e3ae024e72e1800dac247bc125fdafb778ea075e82e3bb7ef4e8417998ff81c561da4ae23df0b29937061f174aee9a44740a3fe5d901d6cd59e" },
                { "id", "202c6adb0e984f3ec059a576145a8ac94cb4019763d878937f44089397e06d270161d00f981eee935e20245159295370edc6294b22bfe6c0d9f4739cc6844a77" },
                { "is", "2697df4465760c094850a2852d9c96a4cc5c029ebca378ffa30e2a1ac0d0a2b9796f601cc61d57e1ff58b73425f1d56544bfb1ae42ee69a7ac2c71f63a476e49" },
                { "it", "859b9dba5b9f91865d4868e6d07a3a3adfda8ba77642ede3b479cc99f77cbb0233ea4f138f379699f122f2e824af8bf0c5868514c8dbde8ee120716c9e6ab417" },
                { "ja", "29bfd32da89ff8ef34dcd80d3eaafecc0e7b2832cac6ebac9c8b3933a9120b11da30940cd1e74391a735e9c443f00303269ba2e39fe2d0b4a38587f152338499" },
                { "ka", "c0eb020ab415debfb75a8ba8d52bd6e167f26cdf9077176f8c3818a5727f727fbd01eb535ddb00f1814d6b2ad17d07071a5ddfbdb388cc2fea6dcbba4b69dad7" },
                { "kab", "2ccf5ddb946c82746478e42dfef1f45e1beff54f9a067faaac879eb5dfdfe06ca050e377434af52b0650a55f79e17919dbc6c4d73954a6d51d28c8542b3391ec" },
                { "kk", "6f2c2d29c11a80133f19c8946d4767319a15cbcbf43118726d5f10c0f3fd2d6fc5bdfcc095f36cd17419138c61f47cf61f1b66a4d4d59472a8118e443fffa24b" },
                { "km", "adbfc1f5b6de4a6c2b6598780893503475b2ee405aad99e645449c850ce56bbadb5d4f35539cddcf7d852630b9b5b9ecb210e41872d95b3c2a3360784b31f400" },
                { "kn", "cd976ab92731402808e3eefbaf65c3c5e117de18de3cd496863dfbbe0376608412b74c3396b855cd17a069a8268d713e7ef3c823b52f53a89eab4abcb045326b" },
                { "ko", "64144837defcdcd6306d169ee5c96596949a60fc4932d2760c397858149b1666ea3c0bb1674218d867aa961e608c230bff3ba4cdae6866ec9ff77a66a83fe99d" },
                { "lij", "d6d866a94d695afec0728cc7d28e8d2fc8b568b0d30e284bce86d8b8822264315f1de7e5fd0b9a8c370000c2aa690540eb4aa7ef346895e1765319424dc375e2" },
                { "lt", "cd2239e8eeca35e4d0ef38701f2d019b3a0d7946d95955fe3373974d6ff7131892465922711855bf409b47d0bc707cdef0526cdb2c604fab36fd1bc589fb7cc1" },
                { "lv", "2d2fe29d79ee926b9e4fabd0d659dab7d1608ab2181dcc4c61cf8b348990b62039a23b04001ff2273b22862f025f83e900aff5340671065d0f31050e9bf18a04" },
                { "mk", "e557b4606ea14258250719740fbc043d9c92c2cbcc2ea1ec4f3637bf76dc9cb215cb8caa91a7d198eb0b13793a378a3a90ba42916bb7fbe6d915ee3d656bd6f3" },
                { "mr", "68384424368b72a3846d79278405a9ceb2df9208e58fab573caf62e81ab68afc02b0a625b9c5d24df6e39e0a00ace308556ce79dd2b4e83a025e3b84e6f102b1" },
                { "ms", "82b5b63c707227d649899c39d9a4f0d31df681930dbddc9c4a4ab802b2d11b0818cff74d0c2fb1efd6e75af3197376c4a4fe0eded35f4794a0e6b2e9136e5ba6" },
                { "my", "359310f6d27431be7dff09bc002b1678b178c25976646a66336b25116699b6fce3fe1278b136d306e8678850813870dd5bbfb50de61d3d1637061471e0580631" },
                { "nb-NO", "f3b33254bd9f6b19a46088dfeb8a78fae607d12cbb3cd1b69e347bf79492cb0515a53b7a8d43baf39020485c0274a6262506c871b066ec8426fcd5ac050fe700" },
                { "ne-NP", "2277d6ecd5c6b1686092fd5420a00a9dd75d868c111108833a4f5b12fcf05805e65d0c5d5d73bce981a4d071159f98f7b75487079f0b46890c4b8c80933e563c" },
                { "nl", "fb1ae6c70cab2a966d482782a33ce8153767ef35836dbd29b41b5886ac500e88f8a9e650c897732e31fbe4b493f59723e5da49662e425fa40a6d69a5351c5d46" },
                { "nn-NO", "1fad215654fc4f2350b14330c0962db9731028186cf630a6710b3dab131650656f8e2bcdaa8db60ac44836179dfdfa0f66304f8e35cb438f6218200e442653a7" },
                { "oc", "3df98527ce2100e511d7328d6a3dca07a5ac1ff5061998cfdfd91965cc0fbc644086cc629dd03d740efdd1f917f6031ae361bd44afcc178f5afb197bf1d7d07b" },
                { "pa-IN", "58761c73a37e23cec54c2e1d4d0141c297bd50899370fe27f8f938cb77fc110b0153c3db79598710b8a4523dc29966d2b312464deae95f307ff0983660e730c5" },
                { "pl", "de6c665d8da3cd9fbddfa1f7a67cf3b61ba8067c9d4e211bf4b64401662eb2c77b4dd20a01c236cda836a3a13e391181c537d4cd81781b4540e196f1c750d8f3" },
                { "pt-BR", "3f2f67e72fcbb7a77f48cd14b79d270ac8187674cffefcda8b51d9d11d4a6d32fbbbad7973a6ad108819e18ffc8f007364cb87eacf8cd57eff90993eb8bd5826" },
                { "pt-PT", "81d4219742029d77f65e008ba0c8974acd85ad162c9f18c0166a9299c1f33f0493bfe0d5521f8cb2ae9b0463b8f8406c0ce2971c52dc31d74c0bb4cc2a1f3645" },
                { "rm", "bb5da014efa9de979fb10f501019b8cac37aaa24cec35cd6d9aa01b777a94095a89dbfb1c7e9c209d4e0495ec29e47509516352ee04c0fada548ecd4f6e43cea" },
                { "ro", "9b35584eb0bb50986efd0a4a78c28e693db33d03d3eac1bd3366bf2c92678b82151b1e6cf16c6ff52d9ffac411c95b8825326214dd30e3f5939b94d7925e477a" },
                { "ru", "e6949c1b2a3148ac3ae29a8a2e6111ccfd62541c9596d0183f590d9395992d651ae4d2b6d31a1009524ce8a02408a1c3549e0d9f17872d2de763faa6bdffebc6" },
                { "si", "18d2f99f340b515aa3d1079bc542588f71fc36ff9e823840cfe154d69f842ccb4b0b6ec323fb1f3dccf43e07d3058de3372845c91645931f645364e9fe9bd158" },
                { "sk", "899ba3126bd7ecf88262db4d3c8062a74e9a719bb012b2d69f7f431cf307db419e9e420a71f47c3949abcda0a422d2337bd2e2792cc8f918ad9f5797fd9ec6af" },
                { "sl", "bc828488fa6637faa9c4157978d1718f078836b8d4ab8df2f6fbf8f16d45f698475023554acf83fc54f2f7917532514b3f282ee95bb9aaba78640f3f7572b2a5" },
                { "son", "67a08c0a000690547e77b9d6621f7d2b2782852a979b67618de3d56bbe05987d980b65dd84252f15c6494777631feed5c5d08ff6f2cd5cf9ebd0ced242a42c1d" },
                { "sq", "d4932ed40326ad226cc12776446ebc29971dd7dc8be0b6b7ce9b260e9bf0986349536145937bcee36338ca7d0705d9c627cfc1c9a8a37bdb22e3db87d8a4436c" },
                { "sr", "37f4c9f7f000b3e0b516b7fca0fe5ce6a394d7b5374749bf60ca2bc46f16abc2121cf4fcdbc0e91ef1550a2b90effe8b2d3bc4280887c93ee3b5fceb84a73e4f" },
                { "sv-SE", "66922e944cdeac5843e4e009b4c3eaeaefb036924cad50a08ae319aa940d5e324e5084f12accc2da23a5eae8a6d627ebc85d6a946f1cfaac3019d8d7f97323b6" },
                { "szl", "5705967a0909b61fbd49db91cf14855ba83a66184011eb883bb56a1e4d43708c4af12417b38a01667ac2fdc0bbdee3999c19bddb0d70b34cd965ec3b0f005343" },
                { "ta", "f50f64a1660634d424bd5b342895c4c8c750051b5e077633fd22bb1f2039bd36d263de0c6697b4a7acbb78bd8ff31c712a2b3e5a9e7050455c74fc81f0facbfd" },
                { "te", "3f429f5de0a9a2b141f4c8bbe994d3216491e62a2a4881653abe3ca3dae58659cea79dd0cca09b5faaeb31026ff900b24a56e17e221695d0ed24b076bf234493" },
                { "th", "548356226db24b37e3b2d0f0b8cbee759841011b1b1ec1cd7f6ca626b01ad7a7dca61e602db7981fa004ba88427fa698ae2060d312fec5fa517a3793568caa19" },
                { "tl", "77c84f30fe15180d3d8412bda5fde41b960ac2f3ea61e42b49f4075d87969b0f9080cc55b6ca746d654604f62fa1b8bc90560fa335ec8576ed021ca6c196ee2e" },
                { "tr", "ae39933a75d5aeff324b03dd76f1214b54891a573778d597f6fa5e34634ceac815a031467f4d0154c21f57ce0335bc7d96cec42714529bcd3515c283d37c2cb3" },
                { "trs", "15864b27dcc0f3d8717e40ae653111195c74b178dac3abe952aceae82ec66f897c1525339d21cc893de8d31b32652ac243c871750b6a154f579bbd4924401f52" },
                { "uk", "4be2e0ea7c3f9828b8840db2667d659bd012806d9f164a12b1b88212c171886f4ecb84b46899783a82638ef890a78ddf506141e39edc4b45563ba67c34933ca6" },
                { "ur", "a6a34775121e9956035c4cff19751b2924612c553585c8d0c062307c81026d18a32e995bf9e594469104a1dd2608c5a8a3a1c5486b2a582ac10201ba6df15c81" },
                { "uz", "0db87b552ac7bd837f9d0a7a0884c9482d64080b97ad83f5ee177619f10a92f74f4bcc9299e752ac6999f2ef734af84d8eb7ae36318c27214879154c909cfa13" },
                { "vi", "00e7e565d6a1ed7b908400336fef286e99d910628b2b20bf0b65700d1838a0e9ff17211be7f3837274d65ca7c969745479bd8584cb98150ca7867f5b7faae755" },
                { "xh", "7f2c318ce2fcd3eaa955483f11dcfe92b9e77182ef69043468ff914ce3b8d2548a0c35716a57d60f6d4f369b36ccdf47fd3ec2f1ea9d8d3b0e6a14315b1fad27" },
                { "zh-CN", "fd0b33b1316292a5d15777a2074d48de62e74ac437b22937967d7f241be2f23dbe34e20d8d4aa32191fb3d2f1db11d1180c4f166e32a64aca40ed18e37b184b4" },
                { "zh-TW", "aecee2c221ab0cd1b46c8e55a9e8009a3f3bb0c78b6cfef1e5122971b0f59c18bc16c6d234f9a2fb0b5768695b6fb77991da49984478ccb97b8d7158b42d9395" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/89.0b2/SHA512SUMS
            return new Dictionary<string, string>(96)
            {
                { "ach", "be64ae723204c5ce8be1fb9e048d3cc7203dc3d52ef11c68402fa048816f4132f6cdef9d4636068555e5c31b02762ade39a77688fed92d77a72bfe1bf65b11cf" },
                { "af", "2b3081b4c4233b677d719b98bf05388f3dec71d6d2ce7cca9c4c723cb149e8ebd629d79855ed4beefc482753f060029db8555b23928ded6063e558fd321d4838" },
                { "an", "f1ff57ed109e33338d75dee81ede7e11785b129d04ef047651c12838d6b9c53026a296cb2c9424bde79320580118bb3454d1d33aff4cf1209211cf5e7d64dbd9" },
                { "ar", "956e475db71496600ec28bf26a8aad54cbf62193bfb085de530a2de8cc5c179817445fb982c31a145e1e4e14971e7a03e95f4fc5034c9d38c857440d262ac003" },
                { "ast", "9ab46974e139ae35da55d97131c6fade0e5b4f255170388cdc96ad70f8441031dcea5f93e2fc2e763eb367d4352b447fd0b8b2681a2ec59c3b289e0febf207b9" },
                { "az", "23ce2651a8a558b0511722a4b42815da96c967209fef212b8e857c01a16f1afd99164a9dfa7909fd55daa5cee087dee68913f24039f790eb0aeeac855404dfb6" },
                { "be", "7ee8f89c004cef78e09946629791c20843c74d82cfa0125bf3cda22bcfbd8c3a8de33d589b9da98986b35c4da958362a9709931d3aae553a9b9fbf6cf11f5d3b" },
                { "bg", "0d65577fa2f0369ce38b3faebf2f4522e9a833d1f64eae36edeb082e143cb5ddbb5d322dc0471852083445f1d2b29b8b671f084d4e2543d5b4e6aed9dc3b77c5" },
                { "bn", "87ac7690a7baa24dac0ab7ac352573d0f15bb96fecfc96bf526d3f6b519f19710aaf270fd0ed3f11c18aba8c8a67baddf2799a6cc3534f021e6690a120cfc3d9" },
                { "br", "076b9024b3b628914669634b6f85124b5525030135adf0ad363056af0a3aca74e9b367113e7cad9876850b26047f1962ca93bbe517481b7ba6b0befba3b24ca7" },
                { "bs", "c7c271c52138f31c57f5140941d8b217dad756030a4629267804a5c3c40dc71c4dc75cf3963d03f11b1191dee22b67d7c07d81ea72763a875b44dc09b536ca49" },
                { "ca", "8fe61abad8c3ae7f222a5466119702b4aa2b04a0e75e89b6cf0d21405a34a4fa95c404d420a6ad8d2bcd6a814775eb9c5cf8144746b659171bc1ec1c474de935" },
                { "cak", "0aeca58b1312636803b57bf820ab13c7e9873494c52e2e6704a8b5aa23955ff01006a458ad60ba9acdcf813975dffd64ee600c33323031cdf2ffb8fcf4099f1b" },
                { "cs", "aaaaf580335476045a3099b1899ad7e958c8a131fe5c6152e2e55cca83b7d7dc95a3c7532b38a7e168823bd86d79d516625a0eec89f9aa6701417b9b56b450ba" },
                { "cy", "3bd05b555cd8dce4fff044a3261b6bcf86de6f3d88f6f9edb444cdb50dae08d96b405a7d992380453f37cbfd2632941115406f97e70f8a0a5ead589ae756b97c" },
                { "da", "527206afc0a3092626b51a8aab776712f8ac820af39781a44fd3d4cf38e0826f8443507c0bc8d5581a35a63576c369c25ed2cafe3f0e71aa0f67751f1d376c46" },
                { "de", "e0e3492f9e49875253285091d69ff476df2c7e082bf17b0624b9e1afbb3154db3c3a690b9aaab52f46026b531e678de62d08173f7e22a90555a223d1c9be09a1" },
                { "dsb", "265a5409d9427a075be92c44781fb956a7496920e81ba4fbc1893a68b9dc30f8ec2618233c532431b998946b7471fd4f92f78e0e70deac08d3674a6dcf439f44" },
                { "el", "0b31b6cb6d8c05012d0e6ac72410631288ffdc76056f119155f538d3679ec209da609763d5891fa96a2d46f6d787c7ed7aed1132a77913e815c08b1a06dfc4bf" },
                { "en-CA", "685226cd57394057ff8a0ac63dc7333e739a8ff06da00b54bb1f3d444b85fd2830b2a251f7a7d780d4e4d159799e3b8175624fb54cfbab5fdd451764d29fa857" },
                { "en-GB", "0fb0ee6d1aba9613c5b797574834219508efb6a0a559c5f4234e8ae3c6ad2888d90192b26d70f6c122c900940b69594a0eed2c5493f5a7f925414872bd43d223" },
                { "en-US", "47f6eed97c81b59b6b3922074951c4eda60372a3cf3eacc41d69ead6072755ff1f98f4f64e8fb00b084dbcec7a8b8381045debc15e80c394594fc0320fedc6ea" },
                { "eo", "476de34818dbaa25c5cf5961cedaf23e5b02122170694a9a1d5484f16da47acc309436ebdd15c6bab8b7fbe3ef9fc83110813584432d3e49bdccd3cbf948aa8c" },
                { "es-AR", "257a3b09494eea9b2bb30c428f570f197e1b96bb3c904a3fadea530f1b0383a7013779f4bdffd6ec19cfe0f02fb785639717506197d34fcb91fa53a6de6e1f48" },
                { "es-CL", "5c2a82ad909f96f9184b023461664677ac1b191664babfdc943808836993567a57442c5f9c637bde54c4b2f0f00a1c5f8c64dd8dad6dd9d0660a5fc87841e0b9" },
                { "es-ES", "95997e473606b560288a317224b3883f8307113392168d5a464b1ae1cb326b14b519f104686cbd567eda67bac24cbf688b643f416186c11a206c78b3a623e1db" },
                { "es-MX", "c7cff025b8c259c273b71da56e1a2e2ed7ea6c8d7278de86e3badc121857dc74de51d31077604c88366a749a9fdd7b262ec545141dcca48569ce96680cf9bc8e" },
                { "et", "6fb93f503e8dde4a588326850149cae9c431d63f7ea1a2766c5e2fef9121c451c98f4dcd982a3e2d1f0c84d2d9a5cafc3f7c5106211edbe6a6d5b86683f495f7" },
                { "eu", "aebc85c17f0dc4735a0c0db5467297eccd1acdd2f652096f99b80b6416a09b20862fa5afcfacd70ad3312b588e49b90f30659ed21c711a9882885a5198aedcea" },
                { "fa", "d3704022fc3f0b77da49c5b92f2b6fa261e186bd34a26da88b0ac228b6024607b777c7429723b4dd0c4c01fcfa986ab44c36f13cdb65785b57a097c5ec652560" },
                { "ff", "7e537acb049ea9e1abecda0180edc0a6230d8b7c2bc596ae2c80396d36232464419833818e64244a91ff3d16cf4aba527ea833f2f15cbd9bc6b6c12d9e2b9ce3" },
                { "fi", "4d9f6d0145bae9d40becfdf637057365fb9411a39f9e236711535536bcd6d05c7f50fc8982ba84fa8361a0b10c67c9ca7bd994f825cce1dc7c07287eb3a70599" },
                { "fr", "3f560263ebe0799f1e2910589931c78471574f929a8f0006d4648067009e5a655fe8251b88a96c5222a44fe0e225fcc3a5c81e31825ae9ff2623d9a0761bf3db" },
                { "fy-NL", "eae1d3f135d36c1a4194e42fe07b5959c0ce334bb58f50c18026cf8b33052560584e5dbd8e1dbb04566d0cecfe53587feb75eda6885f228ef81868c163ea658e" },
                { "ga-IE", "11a14cda8132aa367fcb1ca01545aa701a2330f457909b913b37493c283b3af0557e248f7e1ee6a1ac81e2ba681c2c636cad16240934f3724a94ba14c85a62d5" },
                { "gd", "869758f246d52c7252da08cbec800fe8d7e2061775f7667ec1f5ee463638421ce7efcab3ebbc333646e16fefef7968224a605643d5edce88f20aafb0a391935e" },
                { "gl", "087f1506f2b46d1dd6938ae9b3a4face6feaa09e3c9c09057c1ae23e89515f5f3573504c9504b6d3c5dc0828999a2dba0a4bfc162fc0302e4ae4ab32326b4078" },
                { "gn", "11a57c4b79d28cc7e7a2f5d16f9fd5ef73d9e3af8ef92ba2c1c4051f21c69473bb993b6a06e321e83c2eb89ec932aee2af4e71e1951e8ae379de65e0037bc23c" },
                { "gu-IN", "6b6b11d8176418ffd76df531003f8deca239dee1919588e8ebc7c5e502dd33440ff3310207621d600a451b2d04ea0fb0db5a92a2d0359552a6927b7e40910674" },
                { "he", "489a0fcff5aa831d8679287c2a466cf486a16d915e4a0e2be4b7712edccc2fa574ca6a60d7b89bd75cbc3859bc9711533969abd572104188cfc473d80470da42" },
                { "hi-IN", "cc5fa0a35efabea3c2f9cd97ddacce94b91fb851aa6d6f2a757abb659c891de0869a1cb8bdf0766de85da4587bbe8735552ac46cf279a50d6d8e6f6b23da1c69" },
                { "hr", "26d0918bb96c8dc36a1a7233f8fa42643c773fe488e31a189b76a293fe0c8388d25fe9ab359286a40ed7d1d20a9519a1c7e34b284b3e551e4d20b38d8d87f22f" },
                { "hsb", "c68eae2d6d753e92a8413b520a8e553c35557b4a317d70dfaf84a783dbf61d1207ca48625d99e3af716053ce5361a2ee24a49d3c761254563c343fa53e7f50a9" },
                { "hu", "3ca7e7182d4e72455bc155487245a60426c52f857a35e8c3c109a97f0dd6a32638c5f629f47b77d1fae864ecaa3d01c50c7cd803161bb9b877d2e171c962bed2" },
                { "hy-AM", "7f3fb80b3c0d4b71fd532ee7868e59212b67b72b7199015302806b09a03d30bdc9fef6b73dfa04459209f0d14c46be783afaa833169ce0eee570ec25f2d53770" },
                { "ia", "09f3cffd60998a4efa0aede959fdfdacbd5e93c46d6a9e06230839d17cfbf2bd480f3e0366f3c695258affa6b0a022e80354fa16eba7072ab6e4a25be25ddf0f" },
                { "id", "b96f491efe8a6fabcb24f78091f2fcff511ec141a4ca5afbeb8ed8f92f6b64ae2c0967a61b76dda4e752e26ee8985dd0ff32aeeba764f74211dcfd228fb22938" },
                { "is", "2fc1b816dc526177a0fe72174d8f858c525d88ba6f595ce7a54f8ff7c1196281c77af5e0492b4e426492cb814ff407ab9b3ad64c086cbf58e1467c0bc0a108fe" },
                { "it", "178c5619fd4f2e2fb88b8576986174b2191a036fe5dd01e09a191793068d0b15cd275c34f9244e4cbe87cc3ae2731acbdc5351a8b27db66eef669cbe5a9d53cd" },
                { "ja", "ed2f8b261413bbdf1d2bafd51a9e2a19d7d726c1e42969e7521a9cbe14e8e15b43826221ce85c3914fd25574533c6c1f116fca04179d8e4c7f844ee3492aee80" },
                { "ka", "3989ea7009fac66fab1c0da971cee3f071c1422295996de0c7c89da9c1aaf7c50f3de7c39b1f59f12667aaa0f490392c9d222272d0c46c7053ed7296600d04a0" },
                { "kab", "b2880147d56707878bd80459584562a79042500e38808a3b3878ae9fadc600974768af0c7c15f52b9e21843ccc32511dfe563bdc227c5ded7ef194e01d868b37" },
                { "kk", "e280c18ff6cb1487831605cb0dec2f81d425c65af266f75c266cfe73a46866487e837e1ebd178d374fe677e0c88606eecf4f96e6d9a8a09f0300bbb66c57d8c2" },
                { "km", "b6292639e0053564beea23d71c4d92d995c24bc82e35b8fdd8412508e4e4333b5c059f39fe65de125d6c4d0271a2fade01966428a0ad30a25f6863b1aac00427" },
                { "kn", "0a713de4dcd8534ab81887f5dd9a9090dad3e4755764637c818b3eee762c35bcc481ad718894b8abccf97c0c02c35c06a8af41074f663404182daa9f12196508" },
                { "ko", "7a221e90f0744fe67fba0902875b320eca69fea5d4e79f7d3d0e7e38a5977d9d1a5cf5e6c5516cc170b7ac9e5763967fc8fcef2e2c5f923e8785232670919166" },
                { "lij", "8771e6c87d4564aca7f4e7f1d49cb338ac824ac6d5eae21f75f5f81bafdf2ec63ba3196730a4ddf7821478004a88bedbcfacd8212cc81b8f8bc302c4ca4385db" },
                { "lt", "51ef925542f3f6215d63876b12bf4163f8e6fe3b369896eb944795b883f4345379ecf00e94c2037383afa99a3da506df884edd0ce34b785144fe8ff1037b0bd5" },
                { "lv", "9bdb7abcb97759dee7f255aec24be666a33f7e33da2768ad5d03e5342d43f51b742c381b5a263ba53eb2f84dfb619e8fd156fe5a206eddbf514762d85a6154e6" },
                { "mk", "d02083bdd20bfc29bf5f4159062207cb2fe1bd38520815b17063daaec58882b837880ab03b50fde08ad7ae6dad41f05660b9fd86ddb7fa614ec70756f5c8fedd" },
                { "mr", "58ca0d0cf6c243a823dd629e6b0e17ecbbb30510149cb6faac5d5105231ae09fbc69ca000435b6fbf8250fce5aaac41ab59a9250b8bbe167ed92592213e0315c" },
                { "ms", "0657b6548c95935905d2536323b5acb0c0632a2e816d32cb6782dbba4be5dff5721d2b667ac2528578afa302ae0d980dbe1e5be8958535c07d7c39b7fca85d66" },
                { "my", "54cc0a5aec3256a140143906028f463bc5d23331d1e44cd6a71a27193f1bfe1cbb7e725cd39766758b2d760c3f211e36da49ff7164b618fa4c8de06b86cdd30b" },
                { "nb-NO", "455147fd363bb8e0fd7be332f3b67c26c1c98c144b2c497e2931351f54dd0a8ffda6831a0f0dbb2ee20945bddfcdf0110e69d858159d6f7136278bb2c60936c8" },
                { "ne-NP", "8b4c5630ccb0ddaafc2e8bbed35c1a86c0c802bc06e75d7000671c36ccdfb0ccbc982c8713df908cc6a71cddcada8da2dddcea67824cb7def412ff7a811f6453" },
                { "nl", "cd201904a0453f01e933da3a454ca776e0dfa964cd597ebffe2c47c31abb302ce8a5852ac916e17ff2acd6585fc592e2a6e7ff8a775d04253e6d9aa8f8917f1d" },
                { "nn-NO", "3edc49020aac4e65da55cac0814f0d751745732ee40238c0f0edf69fc57a7ce08878056410383bea9a8f45f124b79b204246ebb2d854052ffee9c5c6c53908de" },
                { "oc", "f7c67c3b90e2bfc3b6f6d5a95591ca488d2d602cd6461d011d4be0ee5f769fb270f7130f9e942b94e37dccc22cb544bba98ba8bbf07f521047cc38e2046737be" },
                { "pa-IN", "75d6475b98793e0bdcfffdeac758b7c8b156550d0328cf6661be5946541edb620299727dec80aa1a68fee58908420d73399a05ef4bf34360c87121fab322418a" },
                { "pl", "94a1996437bc3301842b6e29b8306b1ac722a2b1240e4a1d59adab9aeeec4ed60b0d34ed3d4673243cbe8846c79b7a4096996bb60c249167facafd14e34c8ebf" },
                { "pt-BR", "8a36d3a037fc98a33a3d857eeef89d8b0c7b9dd8eb10a39f3542f5fe7ec21ce1a32416f3d9a5d7e777b89e89bba4b15378640c8339cd01ae58c8a5e572f7b968" },
                { "pt-PT", "3199161fb7a9142207de58569aa851551b0a7876527a48d9e954fe6e4934c1609fe3b9c04641a2ce6cdec7ecd54331497d4efc5b3a40d735b44f78e86af4633c" },
                { "rm", "c19372178023e71012d18a720f4340e3d48bdf9b035e4a7fc19751ab078fcba1277761b2253986e91ca5a2ddd934f17958a852ddd8dc57a1ee270d3cdafe220e" },
                { "ro", "bff930035ca6e6617bc05a11998f363851be9260f3f446d374878a59530acb41d59f3964eb35089945670584e12e26459035d55fb05d3602e05a7d71bc5448c1" },
                { "ru", "4427cddc15b6dfa471acb459e63854877c27480d3b4a0b1ed3aa5c9e70f96876281632a44870e813bb7dbfe387dd211842ebb5e5e2adf216fa0c3450a0fec824" },
                { "si", "97ad1800ea5859221b8578b1c4fb45b83899833dcdc087d2e66522e5c1a5badf9d53dbd231cae179fddff52c2f12b7bac7d13f0fdab2efab6ed0c163fe9034d1" },
                { "sk", "ca29ff12c8a9bf22ea3dcba6b4c2ef46d76327a4ace498e01187c19b32fe97ee8a01ca30d087c2342136a5370c2868178a3b6aaaf0a92c7a8cda538106da9650" },
                { "sl", "847ff9810b43c89e6c9175e95ea6adb944dbc33aa9d6402c8cbf90db3a8e085d616c0576e94432b4f6a0839465d3433ee68b2c31279dd3a820b938a886aac6d8" },
                { "son", "6fe6cce350548758d5049fc80cc9ba1bd88662970f780de6f7c59252bd625334a77ce68e9349faaabcf1224e7dae8441a5776ff9e4617d69b362ea075e909160" },
                { "sq", "c4ede42279c7df1f9eed775149ef39da2fb1212dee76193badcd2f257debf29b0783dbf294754690de1695f9053b4c386b20b35f301da5bf5223cb9ac5d467fd" },
                { "sr", "1ecc983641c5b78ae8825ba3a4707ddb301b2690675de30b3265d0319eafc3a239677f88b01efc52bb2f06ab4a26fa3cffd1d677db075e3f2bb4368498be74b5" },
                { "sv-SE", "c329ce68bc10ee980ea841f5c9535af93e4dd20df3063df524110d7335db7bbdf8bfff09481b92f8fc791062bf237945c0dc4184c29ce1479bb2638547195065" },
                { "szl", "5ab7f04051df22e757b8062493a6269cbf37b8ae128ccbf9db25265041307a02674d891e31a25be2ededee1736283aa14fa03d00f75e9ba2f90a68dad7868632" },
                { "ta", "55a3528cdfa9b16b98277dd1df749891284ed401a2ea9cb69574a6d539f378bea507c15f32fb6c24cbd3b1cde550ea87762d7cece4bcd796360ca19f366e78f1" },
                { "te", "532e10e97358714fab93d6650d9260244f552629c1f61d3099907b3932578a9cc7ddbd3d0fc16507f52dd0865d33cab3a70268df391eece6eee116b6e14318be" },
                { "th", "f2de774265f945c4b0c9e5819e2187080bb8d735eb297eacade42f90741bc360cdf6900545975e225c93dff8e810c86c41067606624476403a155e36f7d03200" },
                { "tl", "441be10345cac970787e69a3b22d2fa2720af54a7f1ff1f5f614c8718a76608d39a6ac97feff79277fa94dfe69edcff8fe66ebf3c402160c1f9f3b25772d3e6d" },
                { "tr", "170d7fa2028582b5a2ce98687691a0f9a75f7b147683c8f0606b8eb995921e69429770ef0c765a8055a8bb355a6a1e36c92807013957894ecec077fb3a60e365" },
                { "trs", "b6698113ff2aad24a7797e5b38fa2a184b85dbabf3935c89d9ebc0caeb0af54fdac237b0780b85e3e31508df0e3e8897d058fbc7d546f3e91799c4641af3aac5" },
                { "uk", "5d7da3bd780da13c0d524f91b2ded4c01252d521ecdb7eb74e4d7b199450ac727f85c1ebd2168ff28910984df6a707cbfe9113c5f9407c2300fec896aecd9462" },
                { "ur", "d649cf1de492f0305aa723ac38b892bb991a0a4edb73422d717fd777090bb597752fbac7d38142845b9ab2261c28a5aa1bf159c41f7ca549c131fd7c1c210d25" },
                { "uz", "eb89c731d8da7c7d14bb8ba112381359dd7c24ebfb07d3d7e1027237c1cba9bbd9dcce9df287dc60da65929d09bdf6c79fa2ad8ed8a0d50b54cefbd6a50d4d2a" },
                { "vi", "a82424ea9cc8c69da9983b294f78ae2e51d0a7ecf8e06f21bd75c37c39504a5dfce7d39301f05fe1a60c52dd8bf6db6a9238635390e4634ebe63d04d2b90158a" },
                { "xh", "1dec50ac41f8c883b4b76426325e18d4f7c6f83e50d7e5d43a4d2e7ba1d1e7134e339af1c6ee17f042f118f4cde3f8412beab612aecb77a47178fbed7b945953" },
                { "zh-CN", "a23ca7cf9a2a3f5adbbbfd58e08fcff7c72e4189fd4cbc3464b911d53c1ec3dd131a2418c456d6a1241203b60de54b275430546be7b61a3a8001ba9795661335" },
                { "zh-TW", "6b1f251dc092224a7ef818967a0b0d35fdb986a585512f44c9a56d76067ca9fe55d8335cc96a5853fedb8c49637eabd8bc2a0c488eede8c24d4be39e458300f7" }
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    Signature.None,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    Signature.None,
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
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }
            }
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
