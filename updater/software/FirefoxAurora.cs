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
        private const string currentVersion = "131.0b7";

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
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a837d6475e8fa30023dc605b50650b628ddfb4c4090535e45634469f82f8e43ecc6705fa6fa18d5d123d02f4cf1d1a954ddb7f145decd21533e87d7c1465928c" },
                { "af", "beb7111f90d4637ede57cd61cd4c3dfc7691173303ec43ed5e6b56ec0dfe4cb39d1cf4e7a5255848ccedfe381c8d7833204a0f056e60fcb302749891d42e8e90" },
                { "an", "fb5c7063655c11418d04afc6809d21b76275779be1f15c5c97e866c5bd3407e5e1962de0b95200c7fe2d736b7362cb017dcfdd435f95e7a6acea4aad128ec58e" },
                { "ar", "a4305863ec0111968272b81ba2c3df7543737b8e681918f2762468da01633b0b624ff62535bc65c3859e604caee0e54271a871eee6a776f1d86527155f86c743" },
                { "ast", "de4bdc117bd88b6216f5d70e02fc824a54535103599467c6c5d9ddbedd4d8c619892897e27e55ff2e6e258a90993aadad9e0ea788547cbccc07da0abc1c1aed0" },
                { "az", "cff09a7231a235a1ede1b5b484e04f93860781b5f2127dbcf890199454889d8f4d668874ea6b0ec3520edb7f43a4c64040616d5c3494ce75b6561c0110df97de" },
                { "be", "db0f6a6f0b3ffbcc760485cf6f84600fedba42fb5c8797e6dd818c10800299af23deeee864f912b3825732af293f8a69d2d8f2bb1189a318b13127297353442b" },
                { "bg", "68b6161d6e5c9ccb42bf815c0110ffa8807c1ab7adf64be128947d141572cc42049998df287b0ffe7e860b3b7b68aca06ee9663ee0ae7d7ea130aaafc36e0ec7" },
                { "bn", "ea15ea05e9103baab577d6f70353311a5c098fa029fdd40b8e89f61829109c2ea00ebfbf0443b4c08d5c931f8e6ac9d251774029d75c577ff6a6c7fb7346aa7e" },
                { "br", "a747074302469b433f1abc6a6e964c029313955801086276bbe6e6c616d81d529a856a311e35bb58f76867f9d0a012643f78ef5cda60a3eab5faf4dc2dbe38cd" },
                { "bs", "36662d3e57f6688959349b3296f6246572679195abd9032b10bab990129881f425a28e3d7c089cd7efc2bcc0cc809dbfa0a84bb0112345d0c38546bcb1b9e313" },
                { "ca", "74f9b61b3fd14663692e6e9a22dc60d0eb4ce139dacc6294fba7cb796d5099cb352a5619c1059db2da0d498b1a02f613e8fb5d15b2faffc6ff81c4364b46b3dd" },
                { "cak", "7b6425ef0448b2568c9a91ef42374d798b43135b8288ab528d22dd2ec0912c97edbb3adee8e48bd9f776dbfbe924481dfd136c0b3b279a7f40a6ecd184b40e97" },
                { "cs", "f91d32e411ce3b58ce125ecc91dfea1b4037b0a500d8b00fa3514f2d103abdf38652f40b4be8cf9a165f92bd4b124e01303c3e2d0cde5acafa3f6dc440b9f336" },
                { "cy", "deed27abe71264cf1781a0162606b188a1c47468d96aa38a7b1ea6bc2906784c40203d0c198c8c1979477accfa497d2160a9e9da9a541b786d8d8039171db209" },
                { "da", "954fbb2e636d65842efc98ac8de9bee8122b436c1712ef50f02ede73c2c34ffe0eee7159d24c4ecfa26bad436ecef0e62ce3d9514b8a2eec930a02ad6eaccf40" },
                { "de", "acc3a8f907fc90127d31c4c13b4d6e31df4f432c162351b845c45c20da3f9fa1efe534f5454c3ecbab1dfd75d07f0b7462cfbf80e8e660ad0ced455a84d21f52" },
                { "dsb", "fbbec8f3aa6424ef2fe6a8daddad64234ff03661d2b276ffcd6466d5d6f87fbc0c515fb820724f2a8522fa77705024375b005cb1f13d684c3e018fd88a261c28" },
                { "el", "603c1fc664e72b3d5c14335470650d9d885cb3a3332c8fef429b80336c7e60e6fb2a60fa5adddccf18dde529720dc78d455fddb42b027c2fa7a978443c472cbe" },
                { "en-CA", "8b38f949cbddace04c398e511f8271c8885d384dee0eb345c6bae943facc30857efc873cd9d37d36d57f8d118bcaa95125507795f8afbc9a28fe3e1c0e92927e" },
                { "en-GB", "e3ed98b44da812fe59265fbf888bfb4af222699a3e6bb7060ecf7b9de0f874192402e5708398071f73372fc314b44e3ba8488d72bd7e74b723b23f8143af76ba" },
                { "en-US", "a44025eddec4a1ddd3418323922b9f4280b4486dcdc44d0e1f5489d9b9fae6a4774592458928dc081a4b41c44292178eb536ec824a0c1f6225daf1ea18820e1c" },
                { "eo", "78efb8c4c4041284e396457f770e6e4116e6d3f21345d1608d55ce94f100c749e18b41eca1c5671a88f72ea18a1ccea519c1e51ff027b78a8c66dd684b565b92" },
                { "es-AR", "bb7f14b8bfb73c0b80958d3d2b4c63d051534baac217106af74b4fe5667a7317c4114a006494423a836c1caa2f790edb3dfe1b5335c3615037cb710837227b82" },
                { "es-CL", "1cc87a0d11add82f846e495d7beea5869289d79ec6a07f38ae042d6a1a2a804b92a511b337d402ac236a4d7896c594454190d3820457665f0e45224267850076" },
                { "es-ES", "e6f51aa52ec255a248a32794b94598dd090cb4efd2a4655561a6858fc72d6e19414dd35a4aaf31499d09c1c2f38837ea02b910f4d959f03a7c5aba395ac2c636" },
                { "es-MX", "e0261142149a437a9e399e5521aa71a81d27a1857f52c09a5f505d385cce7b92f5fd1e64cf73863858f98c6e38dcd93de7edb2e683bb4c93527b19ee1e78efdb" },
                { "et", "22efe85bb1b1a8dc582333fe14d985254100c4f28283517be0b1f24921a97bcfc30e09af2dd7dd1751157f7a676b316e71936907a407b0debed03c4e16eba7a8" },
                { "eu", "c6c12d7c4fd235c07d728b008c3337b8987b2e7f52a34bf277131b8354c429053a9cb38e1cb06345b5acde5ec1c150b25c2fd22f0b55676f9e52afde8b0659e4" },
                { "fa", "35d449008108f0bd857b9c7b915fdce52f129f6e7f74b69c16e8e55031c29ba2189f6835e3a64cfb638afafc6612c6bbfed0afd4b8a6f0a6fa382eba1e3c3744" },
                { "ff", "8e19c76c8f3a20a186c45057680f18b257b41403d1e28a6d8966e2102b14b2969d17707861a89af804bf823d05f99b3e73ecf79d233441b37bbf77ce39a35f7f" },
                { "fi", "2e61bd1f66c617c4f0c02992e2e4abed83867c1cfa550e0265d3d137edd967e5974b41592a2aa7dcc86666bf88093b0ce3811553a9449b95f8413fea0c2e0b3f" },
                { "fr", "9e8c853a3b65bc9dd0936d5a7ac1838f2032f4f9f13a33c208656f28cb752697abc545044afcc1f253e79c166188b45db5ea0bebda55cfa304b0033c2fcd6208" },
                { "fur", "40d0261fdef71bf0daa2f8568de5fcf62b3075a319ee8eef1b3f501abc73ec6959c657bc3984722096b9512789aa83173fec9b6a66c1f975a3585f3ac5f0efc0" },
                { "fy-NL", "91092a9d4fb8fcc41537005445b5450371280997a91a5aab7266942920124e1889618b463b032b4c85049a3d3a54e61a424afb31f4a14f423569d6b7be2dbee6" },
                { "ga-IE", "914f2df73e2c486e461a8cbbf92f961eb06dbab11c948705ae18b473eb7c15ce4dc89b91e169b0b45c5cc549dea279bf17a73ed7c3fc0ebf3ebb714c62af61bb" },
                { "gd", "63a0d8fa4136dfe54a6d4bcf589248289ba441dabd72fab666815859bbd3d5e8dbea5bf0d61f7592b5da956e2670014222f732434dff5fbd68540ddc5ba89e50" },
                { "gl", "ec26ea1316df30fe48781104c20dd9accc272db446fdffc036fa56d8596d5c25019775f6dc7bf31fcc69197384949d8d925f0f9dccbfe40d146798d840ce120d" },
                { "gn", "50dd4384069a409065b5b14832495d0127afb638235c55be3f705415c11dd8a7c756704e818f92742163d693fba215fbaec2c5b39f21669dae3f22942b007767" },
                { "gu-IN", "15f305261b1eee6a2b1e778f4bf84fc5cc4bb5a461dc6b86b9e0ac975eb3fcfba025f926c13db26bd1e28436857ca38e3bea0bfc78267db4b8d2fe9b5b666e76" },
                { "he", "ba745a0cfd237113855e4ac8117446240448fd619526892fbfc53d0b25a0484c80261ed6e0e3b359f0aa329e1e79be7d0ca4b16fc8e879515c374839c9795fcc" },
                { "hi-IN", "3004d3fd57d5a6f3248e8526c3da7b20346db55876a7061aedfd28b264841b65a4591ed45b6799efb3cb0fae3522708b97d1f418154b2439bd4955c4ee1477bd" },
                { "hr", "890694cbe6ad6dda64e96d11a25f1fe02c2b5843c8e99193e2602ffd2030de2f095c721d27109a41dccb2a0b6a8bd6d17633a9664b00f001ab93188ecb5f858c" },
                { "hsb", "d121237b7ec077b21458015456b870a558c501007663dbd6b8de695df44e25e7ee37e48e533c424f1e8d7652503e13b0731834994572d370b81b623ee5eddb84" },
                { "hu", "2d569dbeeb0b326417a6f91f614e8ab936dbf0a19c04af1c65e7f3926b345c14a184ce1daaaa9dce6e795044ab00a3ce00126e7814acbd9d0543d1ac59e523ec" },
                { "hy-AM", "03f50d63da133483660dfac64dc5ac2b6448f6d0f0c4a5b347e7370470c5aea805a05b72d33226044ddb1e1f6cc247313355caf8d652b9da0a978cbf6e0a4061" },
                { "ia", "14974cf78d120dcdafe8d05e8efab3af9f3b2cfbd8f562bc649d067730f060212676d07e5788ab7ab03207c79cf264a7582e3feee31f3cd8f7c1b139a3ef5306" },
                { "id", "4ee314804632f6bada543f436477b6c7b325196e42ae11b9e546fed8f9ff6b420f9ea015efaacc6338d30a776d53b4f00eb863f9ec08bc999a3bd6e067f741c4" },
                { "is", "5772e5691cc5252dd49b5d60ed3e73c94dd55692900908ddda5fc7c65d8dab07a58347ce8461e43e0067b651c1c45658f5c996fc59d5a01e86d5ae769542451e" },
                { "it", "99c4682ef1d7e51d33f955b449c04f510f054e92642ff441226058ae2a90f05be0613e533e0af13b3ecead3706d77fdaeed3bcb85ebef0da488adf9cbb976141" },
                { "ja", "c8fac2a8762567d4e37c9402ebda7479d7017dc803fc40b5aa7a188dd4a87ad01b19db683cf5a8472267263aff786f242bdf72536db21923ec49d207d0a7aa60" },
                { "ka", "75008895637b1ea3af8cf7c9915c1c7b9a1a379c9bbb8b20e25eec1f2bb1193eae2cce50cf9906994ee33ca4b98d930730aca4e57d05a0c38f765acaf4277d17" },
                { "kab", "79ea68b2ce2943a9aab4b47d1e2a77f2730d82d8e5d832c8e7a541ca9cdb574752a6828fdbe7feced5464cb60b8c300a24d6d7ae29b8e647c9173ff0f45e5a24" },
                { "kk", "09892cf8f087a128a4536462e189929fef45966ab985f69cb12266f040eadcafc751f952071cd70d7aeeb9503ee87b7762bbbafc1a0caf969a878875f6dad205" },
                { "km", "6239640c2152a3880a17a3f2ebb923b905cdf88ac7e22003a8637b4f0fdc8b3bcd65a8cb5897dc10fecc17bb886d697dbd6b3bf84810b4667c448038539013b5" },
                { "kn", "774eae4c23c8beb088cd95e6a0f144383bc6963fb2f252ae5a7a19875ba3220d3146ed2820c1f9ca5ce5bfd1bd4a66f7dab5869ca6254b24e6e1ccd50d04450e" },
                { "ko", "9b7d418316b6f19322c3359b18ca3848d57a5449ac3d0604c0cdf1c8b3795d358e99fa18db51e085d95880b855555b481e15766c2e7ba9448e1dc535330ed414" },
                { "lij", "b51e4bf75565c676936a709f85369e79f959475b8a94b4984f24951913c3b56709b762eb356b156e98c7c331b3d38baf1c15c6a27f977b6efe3f7eeccca0979a" },
                { "lt", "5abdd2039b7685ce5479371f9487cff518364dcc18b4b29b86c5c6ad331f5ee8af81603b18877f5dc2b881f7844aaa5900470a9bbbb7f0fad23bedeb58f3fb14" },
                { "lv", "01200a8634d092936d67cef3b45435f05067b1d179e9dcd0dcf8c76d076ecc188ba3262aa4f42ddbd93c121b5f4fc5bb1210c88d9298cd80e11c252dee2408ad" },
                { "mk", "1e92566c5aff72eb5cc32cb94178c11cbd0ef687458153675038f585bc458c7259254d05b95d78985de9a8ce5def105d3c465621ed19046db110e25051ed3078" },
                { "mr", "63076be886150dcf751cdc41b2f928f11e2bc3d562cfaa9e5c4442b28a69b47c5083d97d8ee3a4c2720f44f3887422e0f59c4027f63fba60a59635f5905e1628" },
                { "ms", "1fe27702983070094754f2b5ab75656a34220061d7a76503b1efbc0b76fd46bfe7ed39110866327f3fbad3506bd3acec662e64734e61f14449d10cba051339ff" },
                { "my", "89402a57dd94f80d50108ccf906107afedae2534fa4910c8398a2260bfaf16c26a1c9054fa5f9cb99693e7a3a9b8cf3d2fbdca7ca72cb721e13cd7856465424d" },
                { "nb-NO", "4d6ea121695d55a66fce495a5c5678ae8f34f36cf2adba866b1ec93bd14241e15878bfe09f7f19b01755257c1b6fab7b283d699e073f19661671eecaf70db02f" },
                { "ne-NP", "cf30066c4a348bd1798cf7d1fc080cd284d013cf4fa51bc41c7a1e239b17fe6cd251856c433a47abb088c6cbeaacb43a76986d1a4b6fd5fb84a0dcec81d9718e" },
                { "nl", "f4045c3f1eef2e7dd181fb5dd93be141d6ada2f356ddd34a67ca869d51717e0bf9b357599ca4804df06ed3630c782e4e0112d42a4bfafa43dc486c5c863fa02b" },
                { "nn-NO", "87fdfa872693c32cef94f3137707bb6aba5cc9fed6321f74173809fd8f362cfc064be8e5c64b5df2fc52f1c3a5920919ac5558f6fcd3ea3b014fa9bff40211f0" },
                { "oc", "dd3ff46b3c0d12c8a9297d498cf6cca03ece67010ae3d9a8be952ee8fd46592a44bb227d6c39b75ebfedc2e4bd2da16ae8d8804bbc40664f14d2d2fbcb71faa8" },
                { "pa-IN", "cd794356d196e37f4b31b976a0df14eb1cbd99bffbae6fe7658161c7ef10b2f1a0be4b0966cb1d4058b562173380e45276158c4b090f570e3c3bb70d7dd04f19" },
                { "pl", "95d29419050e902eb74dae1effb753115d67911da5a3786b9d83e5aa2993150a572c163129550dbdb851a3f2a9c0fcd736cdb0ef369ec5247d7b8f7bcf183577" },
                { "pt-BR", "f69e143e8205c6c736a53f75344b17c2f91a02de6b81c94faf6763c17f024e6a57674afc5fe9ac885b93197440b639423ea90e693df367dc9878ee2ad209aaf8" },
                { "pt-PT", "4f7f19ccdb02569109930307e1d79160c2df6ec7414bb311bfaccefb01957afa40c8432eb9b5581cf74b23405b4b5b15d0d5b854870e6acd3d03c58efe51f90e" },
                { "rm", "5e399ca1874f40ab93b27cfc8734f08d7cd7aca72b10c9ff1dca5463e01a6f00f7aae11f6b6feb5389ca8a8a92ab336f10c3f5cb4f5ef052ab2594057ed0a3c4" },
                { "ro", "b942762841fd2eafe1d70528767c1564db810f7fd505aa505cd1d6c985cdd003168584dff2b5103486a547ebab586c80145532776dd2e93cf955eecb5813a74f" },
                { "ru", "68d929eebb1013873a50cfa43d7213a034939380cf67a3de383978c668a0b712772d7a867ce00abd24b8acc49ce5835fcaf974adc1d75bffce2e79b6211c2b0a" },
                { "sat", "14c6d2a38c7fd14f0c644807e6813e3f90871e6868e704070bca070236c200f092e5c5ddb55c70bdf6d9bd4a7956c46eefa91682fbf0b01b27e35c40b217b870" },
                { "sc", "f4d19ce7ba6bd5da25afabd5cca141be9f68d3d1ab7be9b05e5eff0aa25d109f2eda632a8cbfa43be19763cefd9a87329ea17949bcbbf91018164578d9b659a6" },
                { "sco", "6fd779bba19827252932a68419309eedd7b688f09c05c8f18ff6139ea39f592e8ebf759683d0847d206c5f0bb2b60614a7e37dbe3b514d050ecbe7f62337011f" },
                { "si", "cb76a9aa76d2d40ce4689c2151556bf77422ed8c22af1794ce195afedd6e02ed771c0da9dc23e80ebcd8191febc4a6e4f0f64acc3ef5fa31ceebb413bbd52072" },
                { "sk", "a464d4ae3d27672ad6eee5ad0e2700ee5a14292a2d7202bef45c57afc4e51976ee0d1054201d0c050bf89ffde3e12e87d2d75220cd37347a9c8399f345ae807c" },
                { "skr", "2ee34568fe04c6b5841466b54031006c1a1661ed9ea84d2559d2fd86be23f7a4654d61ae94d2aadbc43239d2b9934a191faa5372a88afd68a426bd66282b2773" },
                { "sl", "bf2281afc4b29c2e714255076e554bc7e5092d420d7fabb84412a51b39ef4e43cacc4041ee8f3b033500c8159a089fdf777583e4fa00d3aad6e55ef2e53c888d" },
                { "son", "205f4d071f54a1e9beb37ffc53330826c119273dfa5f5cfe1f32fe34947af973b9fa9db3e23ec5a4018297f106eca4f2df15d65a24c38f32712d923a04d6980f" },
                { "sq", "a04a49de478c7460d14cb8046ef7f7610c36688c83f56260558a81912abce96ed13880aea46a67c7cf7e31dd914aac8b036643e38bf028c4e97c327173b1a826" },
                { "sr", "d2e191af01865f0d99f90f74ddb62cd43098596748ab48702964020aa2edf8fc09a10a7a1645cc24347256323a2a4035861f5a4e50c3af9e3fbf33002d76de6c" },
                { "sv-SE", "f026394ce1901d685b331c9d37c604e860187943b66ff8ed3b28176fbb0ac7b89afabb83b2f29ab902955b5f5f7018123c6cdc5aecb02c69f74c53e1fe4fd50e" },
                { "szl", "d660222cb6cd5ac97ff66e3eef9ff10625c62f0c580aa2a8dc59043c2639ee16594cc3d0f748e285f18bfa6e2b3aaa8ee94babca47d6d549cb3e6bd3e38df89d" },
                { "ta", "c016b7a6739dc31831d7be414d99fec81119d9642f37a30b0aba7bb5f926aa399859d40e6da07e99285478df95bafb5b55c51fea3f3b9bfb987d132732dbe53f" },
                { "te", "b5f4eddc6a7a7c3af0a1ed4aff882e402e1c5229ed03bf263e603d7a97d107908b3b02a541d9eeaef30c5c27836c08c94016d80194f25d60ec7aa1b1b1e88331" },
                { "tg", "276ff866057979a59847ef0b514a94de95b978cf90755d3c8eecdcbba11b8ed6475884a22416bc8e619fd92c91d89abf4b61ae4955cb074083ca9d4a0c904f4d" },
                { "th", "0be76b1d72e64c7445f398904bc70840c3249ab3132bb428ca95b439c27b6db7ea51f6378e127609562229b3ca9bf1095c9cc139e23c384f17af39b41f6f2ec9" },
                { "tl", "0a12cf070fe5ec0d6b3bb1eefd9d31a0b1a5868c50708ad97e39ea7232c22eeda4b50628d4a3d99cc53e25f526a55e3a2e4ed5c9eab5a9fb57f84f7a20d3afee" },
                { "tr", "7ee054f7bd58beeed2bc8608826698842f6cd3f8fe993f2327ec8da6220b7a671b16b7cac1730af517482a4a032e985ec1be87a63a7bef17c9ff1a45d15db216" },
                { "trs", "579544f41a882d191dea8d1fbbe7c53e651842421ff2a99a4502328efe470eeca17d1f29f229f5122bb7eccc6225a080f871317912cefb11e69c20806fac3a70" },
                { "uk", "9d669fff582d2c979d9afc140903e21812c393139a9147949f48db1a578b44d38975283ca0fe3b584f8628f4f481b74f606b5132d88b50971254ba501bf9b860" },
                { "ur", "926fd5f7030f4d3ab0c3c26e8d037609938325a1cdcabef959c7650d054c9b4f28563985a350ec2ffde9c061b1e83acd627b87996dc051978228c96ade96b2df" },
                { "uz", "47ab1a206efc9f04399ddef20ad9e1a219450e19fee8c6eb261ff4b6f473603d751dcc98213dd4a62b0095be3152f1264bb910fdc9c785b39580c13eda2631b4" },
                { "vi", "b515e5aa707ff1b51b3999821eecbf8a3fbca08948dd99d16e1230abeef0cecba5faf1344e82e9091f921579e7697c707e02ca8ce6ceeb8f008ae4ad418698ff" },
                { "xh", "5a9f1d8689927c0824caf30d754121645a42e34d87f5f3ed72bf12dce7b8d4d694be737171c070914b72a86e4d52bcaacce9c40cff0b18942033c0451ee42af8" },
                { "zh-CN", "a7f91227807d5aa8f7177311b7f2e4fab6c933a2735c828cdff89683b675bb294890e6aecbf9ae1b74f24b30334f6ed35b5399f79de91173ead3bbfaf1e3ac30" },
                { "zh-TW", "cd61bed94f5c754721644ed179c5132701df3481fec44e790236f5a270eeab27cfa799cae1fa716c474696efb4146e80829a564f8e9ddeaa696b97c267890091" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7a74ef98c2166718a06ae27b17fef0ef1d8721a1ceecba2e76754ec434182cd0ebf0857db63bab6d76c8e362ad47368f646e413441ab619024d82c27a1ec15ac" },
                { "af", "5824ec347cb7ffc8e18be1c62d5391a5d33e0a8c62a06e9ef802942373dd170bb64543616a5ff8c853ddb59db584d092d1b8bebbf201adea2d9c832de2bcec5a" },
                { "an", "f3ff2b634620340565f956250308dcd32a75bee933f8661d5ec0d6853f48932d93c1284c6084a8238763bf01ac3b3f9b5ff83163dd399d4f8be1e763263766e4" },
                { "ar", "3a78775610915b49ce59f0c8fb4c10606d242cb99af906eb673f273c7f0bdc10e700abc1cd2b1b3411b776bcb72176fcfb838a653ff61b2472b6069e32267ec5" },
                { "ast", "81d77cb760fb35bede509846dbf1e35743ae2d8bc87e3ad143ea66823d0c2014560047330648c9b3b846ffe2f90a3da405ec144cc645465d02f4adbeaa7c58fa" },
                { "az", "f0d7bcd8cef4f828265365b35cd3898ce6a178d07506f31bb7c22fabcc6ea1cf54c03b6adea2a7df76bf1d450906aa3c0a9be210010fdc833de91e4ea4583d0c" },
                { "be", "0fef91956ed6cd4970d4022e72303f47990ca3cd6fdec74598bf36c2e3036e4ac1c682eddf277537e009ddbfd9c123cc1f6f79e50e3cebf84191b9fd23ba0819" },
                { "bg", "ff5b824c94c0ee1271c5ac62d8aac201de7f35706e920550b1e2dbd013e98d0729d22c830bf04cd5cc29e08ed66c118f3bbf3615f422f0128b6360bc54b85990" },
                { "bn", "953cf24b98b055c259aa6dea6f213d2d2705f5a53d019519494623422a21bcf384d21a7b2f205d02e06793f34f1371cb8a59d63ccf2ff5df276131b63264ae0b" },
                { "br", "80b4f868ae18986feffb189fe5bac093289aa4709cf3b496a18e6d7ad0b4c7265354679a026c5ecc2a9425e18da54afcadcdfe8df8c16dc4f9cb842882318853" },
                { "bs", "9fce8adf34d46f82c52a56ed0e7181d75592ceb427d6f867b9423de16be15679088ef81e34306b883fd6bcf798037c3abaa5254c80e9c82f50daa35aec3df8f0" },
                { "ca", "39a42b5e0b4dc5b60438c5f1966c0d92709ed87de18e786c68e8f74b3f707c1f9c5e3725cd615124cd968d260f2b00f2d3bc29965b7b87cde81ac6fb6b929b30" },
                { "cak", "f8cc23f1828e5cea4024609b146ccfd35663f432481886064804bab8825d95cf74d4359cc36e0bf6a4b4728f45d7f22fd45a02c1f149d5fbe29ba1a226dc9fdd" },
                { "cs", "770c850a470f1eb639200f5379df74af5da5c96793cad4fb491d7bcea6d91f0225adb0c6261918ecc6fdea4905d9ade59d1f92ccfb10cd4efb2cad7e9fa71a35" },
                { "cy", "4917eda3a2a43f939fb042b6d17dc9896c1e281d67feecea3cf525f56ff4a9224e0c06c319de9079b3693e9172c5036956f782589366e0444d7746431c895cd4" },
                { "da", "deeb7e3ce60affe66934d532a509cd65c880e62a0aa91b702db40338b5b25bbe7f456a4c42237ef7224bb5d66895c7dce9c9e7208a44df00be69e0e32eef76f2" },
                { "de", "51fc502a94e57ba77ab3178f32dcd35fbadd7150267b8cd7f83d392b077256bada7d33a4a6fb38b0ab287583be830fcce7ae76a0f3326e0a18c05cbe162db36a" },
                { "dsb", "2e8388bcc3712644673e3b7bc786fc02ae98f45caccfe9d5669096a41f4d3d8464fd75a735771c1b0dc0a0917735762b4428cf8e8ac0aaa3e20ac5af2b6ac71c" },
                { "el", "7c6430dd2dd6d27b088240471c25a95c7158feca67ede7e1e3538d6383107ac0dce153fae877efbce533f2082ef1bce61eb1bb1c65315713495065791d679964" },
                { "en-CA", "31c0685a65961fc470ea4a890fba135452b95f537fd7ef1d917738801c4228208f337e26801b3dc0906802de6d17066dbecff00ff8817c344002c6d8ae6a091e" },
                { "en-GB", "5c2c5eb132e87fd9515b2f7cbc6854dc3d06244ee66e92d84398c8c636fdbda76a2b7ed18e0d7799a1d50db71d031f9544cb98789dc88a9b39348f1c9eeab686" },
                { "en-US", "b536aa2b75e60c48a76de3d8f62b92d1f727067ae319f23284934ab0d1e13272931da26a7ca1ecddda4adae6f86494b7116252679a5df2ffd8358276acd16462" },
                { "eo", "54d4430d5bcacb0c772e1440c848fd475f3bbbd6e59e0e880dce92a04868897f28069650c1e441c78ec838c5bcd5d257e8273579af496a8bf0878f9646d08901" },
                { "es-AR", "28858d5ce94ecbd28414fa5ec88a616c65480f684dd2c5acf81184fdcde7524ec1ba90bbec44fe3adafaf5d9092fe3a4488063b3fd80d9142d53f39cb14dffb4" },
                { "es-CL", "48f5199701c7c78529662d40b26dee398018d518500272da45944214d2de430996d46c16a80212ed1c3dd26fb02b1352d35fd0b0aa08fb3cbc25412d82b5ca54" },
                { "es-ES", "2fcaa91d5b85952bfade94a0f0e16e1e39d9a0b8a91576492f0e54b1f8177e9391c10a520e2f87105a479f54e639765183e1e258fd6d2461d00b31e829cb5a56" },
                { "es-MX", "55b23ec3d657f55638c60b7d509b083e5f2c76a33f0a90fef219cc59b7265c2a74cb0f8533c551044fff2b75b9ccf83c107326584ac899630cedffb2e142deb5" },
                { "et", "ad891158404397479f7b137877c3a3fb157f7d0a9c698892e34c85ffab95b9b0549c600b0dac438f101acb07f2435a33ecdaf7b53cc2669123618517a5fe979d" },
                { "eu", "50578869f37eae307a9d63f2c02638558f270e7114ca142e0cc86b33fe80052c7e752a60cd59645f36228676e09f098375a4ad58adef85ecd853b6ccf3a4b1d2" },
                { "fa", "14325da6576825c32969d86f92f26be86479a9bdc6697814448c485cbf4755c6f0093530b21e3cd83e1ba35a53b57658ae0294296dec824a84c262fd120b312e" },
                { "ff", "b913163cf8e8d140cfc6ef85d0f3b9852fb7d6504d87e129d3dd938b6f0112b1daf705dfc28977796dd67ab868d012ca51fec6fd2b6de9aa2a8db89da7f28e33" },
                { "fi", "ec2a7bfe3e49a504688ee4df7a58728560a23a6d449234a9f35d6f64d27e4746235135362358a83f0cc527b1efbbe896c0e40659a6112c4d8976e9f0dd58bb2d" },
                { "fr", "d50edfcdcee647f6bbddb625e56d6945b99eb29f232d5c9619048307bef665dea0b32b5981f8f7a51334968def5ff22e82ac4113fca8e4c17e8ac7aceff7fa9b" },
                { "fur", "8a2c4354aaeb92edf48875dbcba9662cdc8171260a62e59d21cbcb338cac0b63c6b3b0a428a8deca95fa25b86c401b7d62b73170ec249546335cda9428cd791c" },
                { "fy-NL", "d7f206780acadfd9662cbdf4d82aecf1bd37bb0eb46bd93454185f3196d013e9d5ed5b4f692737547f21da4efdce7b37e83aeceb00d0f573ab208fd3bc23bde6" },
                { "ga-IE", "734680a1d42e4c72810ce4f9c6dffc3807785ebc6ae85c06129202c8db6c923991dfbee765cea8b3543914be03c1bf7eefc0960f9cbd43815273130153a90055" },
                { "gd", "eb21ef44f894bfab8d3258acf176aa85d52b1147669b5544e5cd002dc22c55204ef5abe7b3a69501947822798165d33b6d1d125969312df3504f46e38c4f35e5" },
                { "gl", "c6122e523a0a8abe5aaaaf3adbe52e78fe207d87198a4f829f7c91630b968ad6c9d909b2b8ee655001cacd6ed2377df0d773d572a29fde70d0318bf198faac4e" },
                { "gn", "554eb95d3c5d6e9e22145134d8c6e66bb74f70223d4344303512d2ed4d212fa5b8fa714e190058ee3e484c73eac01a806dff5f45f4cba028fa9f547e0f141f7c" },
                { "gu-IN", "32a8c873eb3b2296cfe6ee5b76f24f82e1020386505d63ae6d224ba8f6e50cf9a1136dc1948278705251b087469819956189a7f0ad48db2273499df0fe2f18f2" },
                { "he", "608060185c8e0bfe81d08761728fdc516dbbd5e31b4d3e6315bc32c93607e0d03d7e4650e29087aa9bd3f3c433c767dce793181dc429093947faa8dea97cdd7a" },
                { "hi-IN", "6aeb61cb19bfe1bb8e6517556b050120965dc4a8303bc16222bd9adc821da32e243842baf41ad804a73d14f91d213ee01b734215267217858d58822f345738fd" },
                { "hr", "d77d7a543e59889d54749ecb7780ab134d4ac692203177297d8d078aae101bb0629d9cfcc9bd0d3e3c5315fe96b959951d389a52df7c9bd7aa13ac676b170020" },
                { "hsb", "0f3dbf41e74f38b25bf0d8e9f6031356e0aa4d5fd7606c49f2b37317fcfe0e70016d5d0fde6f6651f4453b76bf9276ba4636dc47499abdf4325b08e523cc911a" },
                { "hu", "c249883ef427ea5909e9275901a754716552cbb9393980e83704a14f9766fd362595d8627ad5f6a31de913cd31f82763a7a64bfe1ab9a1c1fc6f02e37e343384" },
                { "hy-AM", "5feca9d1c75edfb3776987928626a59b4f271a6eba9a04c09126ca04006d164e10ce2a0830aa14d41ff67e9ed3e98eda58a046b051f0c368fd07572d7388edd7" },
                { "ia", "bae19977b127a671e714098545ce29c35e5ac7d45af173251fa65eab5b7bc7a6f82688862bf473345b44f9550ad91c8646ae04df0c191b419c1a4b8f419302ec" },
                { "id", "7e75ade24d01c3a3b4e714b3b5a575ad826f420afe26baaef4e73af4e579ebfc63697d374526b2c259b1ab8f9a39801caf12bbfb154563b4226da6927e0f66d3" },
                { "is", "9bf526a60ee5e2bab016d1dfe556f1803df1d4ad443a11ea61ec59ba79e162c0f4537a3cf828a852a35e983166d0073497e8f7e340792fcd1e38704d6a40e7d6" },
                { "it", "1b86156036eefe55f4b1f76a762293c220de9a35cfc22b505f2b8734bc1b6ad71f8792904637d1de106cef574143044fb40c721a33f7b2cbbf92d9776cdfc7c7" },
                { "ja", "3a9529d27c7d498857b08273e5cb568068e9f1f9eef0fb630d219bd2f96c5da2fa87f50784ad039dd27bdc850b09a467fcbfda1d6c60649005f6edea408510e2" },
                { "ka", "4dd25eb35b1a1d5f7d58de300d783d22da09204aae84be56164d4502323f4586b795bf339aa2c714dd7673b598767ba900b00f575541ebdff0a83a2f01a5eef9" },
                { "kab", "45bff5ac6dd6ba083e8f2be2e0129706f8718ab85a6f79691cf0ec9086f9179b854f2dbf5586da4eeeafee665a837f94dfc642ec21fdd23d4eec5eb4c89739b6" },
                { "kk", "af83b41a8db9aa4a598bca866d18173ea87c82e3c402e82cd9bd40aa4b3eb158c21d28d7e2d72ec64c3856e1e8dfd2638b10d6705444123674d771c3c941d2ba" },
                { "km", "c5d5c991ae31d25b4566d86e5dfd73890707b60661e57b8ae29f50dd7e67e3f29cf0d590dbb9c0484565ce40d2ab707fc6b8cd85d741d7a2250ad8808a9e64c6" },
                { "kn", "630383694dd7559ef4404c712a4e9ee0c3205b4345578b996cd8f133960fec77a736ba486efd1756a8f0db4afcaf6f1da77ff1ba6b2e2b809198b1588bbd69a0" },
                { "ko", "6d5ddb36215e6420a7c54d216278ca447542c736d13423824ce57568ba2861c3ddf0d384053188723784fecdfd5f1f5af3c3fc838f8eb7e29d12dcc1678f7bac" },
                { "lij", "2e691c475a3f7d7a212da1f72b9809b80a5a978b1b36dcaf0df02f9c09d475a04772a67be2837707ee9c209fbdab3257c1322b1f5e14e62908c829de586b56df" },
                { "lt", "5feab390bb5245ff2d6d1573e72f15b086c31dfaacd7719ff4de526fd68ba30f5a30910f37724adc53a07783589c346093a8715c042594c0a01769d99d7d3ad5" },
                { "lv", "42867a43f0bdcd87bdaa2bc2c9959d8ef6fe37381d67d1ecaf30a2a0059e0882d5e0cdf67d6af5322c11510fc240f5d39ea4d84e45ab0bbe9d648da1c2682561" },
                { "mk", "adcc77c8356c8531822c6663473bdae37bf0ba4722501d2465473a0e8c8af661fda3b3893379324a6e3ef504dd65f220ddb93ee50a7f6b5d940a93a823cf7260" },
                { "mr", "78be1660d5ee46b3133f553a9c700fb7c96e325d70f7267e32d7c35b4a8fab55e0c6f6c4f1c34cc1aa4cfed5877fe60413f5b7aa40f94d7f4834048303ad0d6d" },
                { "ms", "32149c57ab8b928b196e8994e404591c82afb633fcc6a2646d800da1144a1f43ec8bdd228631ebc59c715067d9d2aa8d2164736ba225863b40d20019f1695af0" },
                { "my", "7fe188f11491891ddfcb5b8f1b41bcad87dc98707901c09ead6ec7e1a591e7664205eae579b03fea166e6dd9c47c3324837d0956a48bcd9471cd4a9cd7ebbd2d" },
                { "nb-NO", "bb186d11e24ac7c7774fe54488bacee0efd7f750c5c2e301cc4000f4a9e450a355b48321bed87da43132b4b32011c5e131fdcbc718d640d54dfa7810c2cc325c" },
                { "ne-NP", "9b4bb9a7b636f0d1784245e9897b03980769dc87cad40b7d8034174f64d2e7d57763dfb535a161e81c74644d13e078e6c7846e3f1856001e5744d5fe3d1fdb36" },
                { "nl", "45768a9d6f960b98a09adfb8f7be2c7724bae997fb0aabee2776007c0552a8bb7efb094362d04de3aba341018bf440731345b8762e671fdb9b792ea8f5c6fe31" },
                { "nn-NO", "743852acecc50684028b52fa0913ac8d012b9ebc6292cd90f747fa18a4d2c980088b8838419a12349745c0043b714f02aa9cdb39ae52f7e8d6a4700c9740ea76" },
                { "oc", "3c812f677b21e15c1a160ebae758ff016b214064726bab88102ead6dd396e0b9d092a0b5881c8d10aad6ecf7628415b62d996ddb670f084bcf7888b4b4617240" },
                { "pa-IN", "44d060d2c533f7993fed0ab4d66ec616afa0d3e013c068398d5e71af11e9a985fadb158a9becebad38dd47d3ab24b6cd727405677f57abaf39dba6223387f591" },
                { "pl", "d9365cf43ae84cf8b9a73ddb89721b83f5bf58da26445ebacd02ab58f6b1025f82f2077645c5eeb8d2ef2079a356b9c12d428b8d0196ad6616fe4ae301ac2c1e" },
                { "pt-BR", "287eae4508f27aed1ef0f816faf99019ad3ec294bb7bf83c0b347114b3d74e73b1d674fc43f1037633903053759addb1088a5b2e1c613517857aa079de6c7ac2" },
                { "pt-PT", "b6735f3e02ba5e5f36e360bf82a1e11743bfaf2d75c0524c93cd742e61de7c5b11975ffed092de460ee72749220b528a360b1b03dc403eb6a68bd2aa806efcb4" },
                { "rm", "1a362871a44a2692e8a945de646baabd4c6e13ba33d91046aba6145e47bde56e5a147a1c27632ae4ca7153b40fa11ac20729a8b65d63f26632d0cd2c938d123f" },
                { "ro", "c762c88bcb9bbe1849f9ca5616f37b11671d8935f6fcb60c4931cdcf0751c28ab38e8401a0e430f8d8b0ce9c1d2fb8c1c9285671db97b7b896df4df0c9e4176f" },
                { "ru", "55b7a44816fc7c262a7323928276004d6a7404ebdc86e8fe3c77f773f4e8f6a65d6099e769afa3a0c400136f6e284444c103bcf28d9af603ff13586a49cbc108" },
                { "sat", "e7a0da98a38be50c7b5134fdba7d5c05bbf01b9e343f892b74e7f11f806f0ebbba78429c7600424ab1e3b2faa5bfa3b894c4fd897cb873d5d7e4d4288ea6e20e" },
                { "sc", "536be82820c8fd1547b55341fac6a4c97a4105e485e1712f6ea381ae9a5872daca2772ee8755a3177bffd9c223ce885c20794a17bf0f67010e8215238d33c8ca" },
                { "sco", "0f5c606f833e1b501bfba586d84229fa2d24fc224b8a37153178a9a8c22c36940f66768f4388e1428afbbab6dcd2414475683d84b5d8c38d562158a88f6b4e6c" },
                { "si", "744a04f3b81ca4223b1657ffb7f5052a29a9dfe1c8253fcf5e86b66bd0c445b047eb2e434a688a9adbdc2023169510d39db55e09891b4a78db590863a1745e21" },
                { "sk", "4a0e27faf80274c091f264ecf27b52e60aaa5dc31286a75da603a1221edbe940123cf1b634f88fbb761f332fa90bb45cbe8ccc9e09ea029c27eb3d801115a99f" },
                { "skr", "48fe9874e8b9accb773ee175b992f9ff066af55eaeeb0d463ab38c99b8d2c0fe20e61f13cbcf340258a173a84bf970210c833b36c7c4afa6b37349fc43b634e1" },
                { "sl", "16c53f7567c911b09d49185467c5a079064ef70b43c23f9887a6760626956f0559c1b0b9916b9fc3f513d3f0abf9723d7492b9163e4c8c44e80209f0b6a5b841" },
                { "son", "f448eb08ab1c2212833877f42f92babe4618905fc0e80a09652b46b88b648ca781c41895ae407198129c8de58c1d9ec829a5f87ac2447d9ebdc674f4c1aff003" },
                { "sq", "610b0dc281a95d168ea3f9609967779cf844c871f4f27785b6f60763dc33c0d436b688434e036ebedfcffb7bef5f371296685830379583a321a3244889bbaf03" },
                { "sr", "2bb0ebb81f1080dbb72eb3d4fabf4f48394f3ae5e67961ecc1cc9e12f8aeec866cc5e9b441c2d0b5b25a13019ac03b5e90368ee8b29bc06e165d648105cc2eae" },
                { "sv-SE", "46950a1cddd11e89ec4fa1fe0593ff6e2306e6aa266b48ec55d5d845a04fdc40ad61ad7c4002085aedd277fa16babcbfc11ee6e4d9cfc7729540db21504c5977" },
                { "szl", "d44486672dfe0b078ac7d12214a3549a206b2268a4888b8101f2496135093414f9c9e368da8f23cf70299553c49f2ce312d190574f08469ba71ce2041109718e" },
                { "ta", "4463469fc18e1a49fae3c27ecb2fa2769a753c629aa104bd4f9d78ab7ee282db63438d27a411d91c3cca4ec7a8d6667c35b7a74eda08ea955f443e4c66caebfc" },
                { "te", "7371395f0906ef18590aa5a165baf4c120e3a81f5f68fdba0583db95dee07774d972c98ed2299f6c750971f40558a7165be38ff5c60163fa4e6b40d68cb9cb52" },
                { "tg", "609f280ea253ba1f5ebd54cc2ebfa1dbd0e10eb44ea409f9b9f04ef3c6e88df39175af411000568cfecc92743b698f1b03e63e1f27d4b80a772ed125d3a142d5" },
                { "th", "5c99df47724f991a5791d40daa0643811f361fe62dc6e3409ee1eb7d8a1cf692097717f3b06f62f874da247eca3faaceca6577df0cac8ec248d109f4d82b6370" },
                { "tl", "871609da41363edbcde70773188cd587e89aff0911db02d7bfb4002935657d1f30b57e9a1d3a363e7233142c15e5074661662b928129c8d06200f4a5cd68849a" },
                { "tr", "e1f75bfd80e867f275ce4647c8da8688ba2262011dc1cec1b07bbd58efd26c98b453ba94cf0d1ba13c2b4d540c6b86e1151ff0998051c9c88fce995ac16b08e1" },
                { "trs", "0df47e0c77d49875ac2aef1b30451288c882346b6af594c93b1f27288c7ca906f3757440fa80304f0a0170276756fcfc47f58558feeca98a73ba249176ecd4cd" },
                { "uk", "cc91314f96d4e9241df8eec4dfb387fa5ac89c27edcd8f813c7157e37b9ffced832d984106970177d4c80b5c2156d176e3522e604c228ca89f24e2730c2289ad" },
                { "ur", "2f8c9a14722aeef9d5acc7f2c63ed4ea3011c25575b05b84412811476ada65d66129a2712fb38c968cc36e4f1fb419901bb440ab7a927dae894f03c484daccd5" },
                { "uz", "7b789efd39b67b17a6d1a0e8623ad347b01034759e2f35c8a9ecc2dfa63fc7b00d5fff2f5d67bd3f76b8437cab40ad742fcac6a31123517febb825a4a8994ae9" },
                { "vi", "ee4a85dba552a4be453686f64ac6d26b53c7f59790a3a3c0a3466aa1695f78df9ed88a36f256a1a5951786e100bd4b322188340aa43b0a557bc62c5149ca83b2" },
                { "xh", "e5eacced502d5e6b40de10463f6ef27ee093cfeb8a11fd0f596029c895fd1383e02e0342e9eba1a3eaf8c1c367b6f5bc909462f50405e4216f1f00fdf4a2dd31" },
                { "zh-CN", "761fdf7a1df00515ae5fcbd374373478308e2ad85a50a86299636fee7d57324a0bde87a7fde5feb200e64e8b78bfaea9e422e982821215fefcdc76935adf4096" },
                { "zh-TW", "9d109bb75665a510e6a7b4d5f73576733a3fb582a3c817b248728d9584c1df10cd1435b96656ea6d2c5be84566f87cd4d5bd4a60b0df1ca933a36c93cb3f0dc4" }
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
                return versions[versions.Count - 1].full();
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
