/*
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
        private const string currentVersion = "136.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/136.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6c86d2d6014b0fbd8dea4da2b05cff3f378be5ade0c06ac3c2d1cf5ed3922eb1bdf5fdb976f60e79dfbbfca0015f3985e33077b52e39ab50f316aa344ce6def7" },
                { "af", "c1d5c194193053dfd00f4908439d9915159c23260756b427bf0689549da0843dcf56c9ef43b30931132f9261fb7f5d36eabce6b842f3a8be870f8e02d8edcc70" },
                { "an", "4cab1b327de9561cb2580d5917b14fa43ad648b42d5d7672a2af9facb501b19eb40e5ccc41087777fa1683d537fce12b3ba95b9be0917c38fbd7ee89a237e0fe" },
                { "ar", "f0f397faf4314ad6206b3f28ed05f27fdef420a1cb95464cb668b88d3d2f71c3112a560418ec7e9732744383a785f329a61789eca549402f5cbb44a5c9db4735" },
                { "ast", "2ccded2ecfa71f39a031e8a8e09b57a7024c4e1c66b91a56e7a38d7165f3aa2cb07a06283f1777b9ad5d690ae8a39443139a799219a6f6c8ad81f1e3a6a1becb" },
                { "az", "8df4d08e14ee4ee934d0c93f29bf4a3cb724b3341be880e77c075189c46639ed99ca98c65564e584de1c1c548652f06a9c79b691207e04e43584247dc02c2a21" },
                { "be", "5a5ba9732e1141a473769e6a4e9613b1c7f35a2db4c5252f41b7c8e23028a8e88dfa185de3cc8dbd91de8c154795f947ed91aa20f3158502992c6cee40155297" },
                { "bg", "bdf0095c812b94e17bfad4d8769dd1ce474ed1eee3d2beee52eb071a6ba96c4699ad2446787eee23648b505343286032ac4d19198a94d03c4d7ee16479da2238" },
                { "bn", "9a93640062800ddef6c00dbacbda9aa5d213e697a9a2f8aeb549737ae26c43ca4e198a78bd6d14943548f404d75172486085c7b17a15e2515f505677ca852609" },
                { "br", "489c3f54e31605f4b495b245c4dabd294928e456c29b772cbea9d8e8d3011b0343c59d802ac730f71cbcaa39800592d271002a2081a60a7376068d345324e964" },
                { "bs", "26ee73c038ed165175dd05b8dfe5c08da90fd382557bf81c46885845557c32655460b882257d0a2fb59931f83bd5b2159d6df2fd03c80b4cadf7254375d75344" },
                { "ca", "a8c948d2b2169ba643de760e14c877d2a471c6196b3560be3aa2687a074ea6cb18dd8dadaa6c4e2f286230f68acadcb5518fa46a41f769031d26d2d36a6d475c" },
                { "cak", "df040effad0544a782e2c3624e3484e55b4072a1e34d88a20e5ca65c460c4223e8e35e6a81b80519408ea1a073f4c86ab1dd3e3929efdabc4f35b32225034411" },
                { "cs", "e084aa2369353785f5331f06c05049a6a76c0279968f97a5bca6a55932eba43f6cb74c8b0d01d40c0d5c61e9df4eb4ab99b095933f31eeae0bca6c0fb108d42c" },
                { "cy", "c0c4ff04be19715720f90d0bf0d2b3ee0aa8030739b7cb43fceacec834d4bf4fc282e540cfb42aec2d61621d7575152b84416a62d2c9ff9c617c7d40f7867321" },
                { "da", "5fbf51733c1f08911d28fb8a229cf6675621019867c9ade313017d0a3f40b57e94f223c69fc33f87593987143d04ed29365cfd1edd407f4e39a6bde9ddad713c" },
                { "de", "ac43a4a08ea3350000ef50d179d1e3b9e5288d10666be178f07e28ed6d03382b7839455e103398ba1409a5f5f97e0c3344bf268e490cc69a76fe7d4da8610159" },
                { "dsb", "f6bf58854142ca25d5113d7ef71f89b910021cd30af8e8e695b525b0e7308688b7ebafdf1e83ed5c30204fa35881ebb617e7c45475348e5d928e8020bb830d9a" },
                { "el", "4d14e85d7ebbb3772a3ecfc7aac765885250762307994c5cf4b3a5b7aa8ee8523d5c05b9e3437b15815c9074d5621b8f40c7132e6d5199861855dfccd51c36e1" },
                { "en-CA", "916c9fef8137e42cdfe6fdc2ce9125d9b0c29a32b0941eed8e9fd872b161b79d30a9580e1650ce34f5bb631991091822c0281c953bfae30434faabecf65dc54a" },
                { "en-GB", "90f7f01d28a0d70d7b6ead6c895108fe965a165a02dbc39cf97ceace6660d8572d9667ea78f5147847c99292d8865fcb1effddd8f6b18a98272301073df905b1" },
                { "en-US", "f860c385c90f3b712aa61c6ef76978db571cd693b8263f8a48150967178cd0ecdc830b00ec9da2f4a5985e9bde33103a959d357fcba4270585eca15b220ae0d2" },
                { "eo", "92b9d66a9b1d404332c02dd90e1fab42a8c3736ef112a5fc30ca876aa5c4926c30a19649e2c75d5cdfb024fbfea87402db678be2682f5350af4f8cf4c1e5a113" },
                { "es-AR", "46667222a29fab7e6ec5fe56f6fd7372bcae07c3240775a0216fa39bf96fcaee57ef1ef0bc5827e31d1575f3db51fad577ac98f31781bc5783685b18b53010db" },
                { "es-CL", "0110703eae0d2d42e3c6b6992f40b94336b0c3b580e184a074b486f85cd43c0d798fb7a54522f0fb9e916e866d73be181296d98536074b398f35d822808b67eb" },
                { "es-ES", "327a22f07a3cd19f9af4b0c673b574ad92d1b94e6a79593fb79f168ecbd47511186abd22b7d64cb662ba138aafce6db1a4b93e50c22d1fc2330101071d8b6a52" },
                { "es-MX", "15e5890eb2dd506827368ba3f96d4ef0682f89141c86079a80a62d58d11a75b1303498cc025ac2243124718f6b219577dfc243f525d433ea6003f536d8c40933" },
                { "et", "0fc762d01e3dd4364bc9de1d4d127d8ea2c196f9af84c8fc9078dfc3c7962dfd98d923827351f4c87487001abff636d0b65fcfc450a44b30cfb33c460cd61125" },
                { "eu", "0092d5b5e38446e99751feb3c326a3da0a684c0197120a79db0d5f10860dcb36d05601c8a8093a1f76dcb558a6b79ecf04dcc1d76194663fed05f0e578847b43" },
                { "fa", "45c03181c2155d1ad4eb4ede2d9c2833a1057a82dfb4ac7d0c08634fa13105f98caa21d090d5ea33e62a707e10bd7b8a876ed5dd68afb8c8150e2d07c2b104c6" },
                { "ff", "1b97cca5177c79d5581e9aea7ccef1932afa62175dcf00c9a83fcc152eb9c243255bb3f23531c1cba325b98b3deba5ea01192e5cc2aaed8b5630158fe5975baa" },
                { "fi", "7b8c5697004218c9911b3fe5a707c6135ad90ffa3fbd55d6bcf49b5a6411657b05feba1632288ce5e23e3e6ed5b16d3fe6af5b1312e1b7d016187bd981151723" },
                { "fr", "3f0029e26d3e4020e39c720778907ee3d767e942bc17a5111b1b39b71766c09d2c07b468039b0260febe6f53233a02cc0dd39a4993d9fa050d0d804f9420652c" },
                { "fur", "157dfc8f077be798d12631cef998f9831c620a851475b912336203d42921cf3a4fc96b689321631f80463c58485588aa61c8411d32db3736e9cb8390c1728a0a" },
                { "fy-NL", "daca486d4256e8e02ce2ede6dd3f397764fa7dcefdecb81a369afaffc9d4bb9863c498b6421daf97493b1df72514ddbbb55150e363ba65cd0ff6f36bdc9c876c" },
                { "ga-IE", "cb595f321ce1341743a5d20998efeabf62b44e3a5e7e8c25c8434726d0863a86fc7fe694650bc0f69f491c8be1410424eb0f1b2d1da1b676494cf768d09e10b6" },
                { "gd", "985e94263c6e193907f54c74b4400c21d7086c54b621392c1a3e73e9646ae27593fc728c9c529ff2b8e2b9647e1b1155374d2ab96b9a7d38058e52a1a755b16f" },
                { "gl", "a5a986ab032c833a04913e78dad949267e08d2143ff2fa21b090fd15028164b148993145eb12b91e1c01273dece195cd9c98729f49e9b55a883f925902a4d74e" },
                { "gn", "92271064cf8e3ad8b56e51042de21f9b96adf2b47603999f114fe9486648226519292314469023a4c329cda82471dd44d8426b1b42346a9ddfc7fb17ec662fd9" },
                { "gu-IN", "1bbb2f39ad5ca65fd8efbe89e73effd82096b43ddb78b00867085af28fed2438a16b1ae60b75892d09654fae593da3c140008d4bc8c2d00bbf170ed69f99e4fa" },
                { "he", "edbe89c26e76b363b095daa28a7094f4ef09a7ea0c9010b19b29a785fdea2f2ea65d054cf1b3a929f7039f2cbc58ae8fcce19d8f1244c7c2c1ff0cc1eb961d19" },
                { "hi-IN", "3186d81040c957f0dc9950b261b98b5a0f0b3a2cd776779337dff5477618cb861bc98e7a8734c2658c8243ab0895dcc7e9061a73f8f4cc99eb22ec09d2f22d53" },
                { "hr", "f00adab89a9e7662ef66ee1d889e17e6f0744d07667a2aa3a3f0c05b741afd71fdb205f6ea5eccd8ea60436ad3c86716c5d2e93d0305fbbabb458dcdce8a4ff5" },
                { "hsb", "49912232ca1dbd7c068d050a895d314c2d43070bc8c21813782ac37a61ecc72d353d3e0f2f18bf558d7b4d2e303e325b6c814a3b8e53b168d8db1efb9de23fca" },
                { "hu", "7cf9111a4cd6174bc46ca7bafb764188251a86918fca1300904886053e5e8a4e2a803ddc90588ced62e6f1c089949807d81b5ca569e5979c2efc49cfa1befd63" },
                { "hy-AM", "30b46f984216528e3536a3fb980adcdd4d0e4bc750920b22e49d606f7b3090c9324b12e5214e6988d222fed577fe1580d60894038702739d9e86f48675285ce8" },
                { "ia", "899144598817e3c53f62312e3ebd459b7c1edb6f79626baccab4b8e4b81f88cf2f59d2554d2feab87c1202cf350a668b8832ca3fc1bb182d85ad9f0f7ee6627e" },
                { "id", "9c0fe350fa23e5660ea089138852cf9009b9ead29ca3aa3f2197ba3771e09f9d1d69129639417a986e0eade5f0f0905026d52750170b394d005ba3bb2579457c" },
                { "is", "2997e58bf4f6c61b3d7cef05afb68bcd14282ce3860b55e3f8351b0bcf630bcd95d72f96d5a01889692f682d284ac6fa9c4bd4726a7b34c28a3f9be9e8154275" },
                { "it", "132ca613aaabefcf397a0b13072329c3cd2f164a2d868515f3635451e671954d95e73995dff538846a53c246128297df92c22611d0ba9dcc78ff75404b4f24ce" },
                { "ja", "4d5ea279bc1d68903f5eb85deac3c661e6d1544632c3b735d57902df25bc77429470693886d495452a46a087de9f61911a2bcb927ee658569950435ecc958e67" },
                { "ka", "42bcabf173c7c353ab834a9a2097f60dfc66a133e86d2bd515e4d982f827af9cfafd0197df3c466dbc4bc571461c6fa8708908fb822739c176e9ea653d76609c" },
                { "kab", "554a1b960cbe71b873a7433577789d33e58679f626e8bbe09696c10d33ebdd8343979921f5d783e1e5e920a6f72076a2d8dc692282f8787defde9a447b96a225" },
                { "kk", "77dfd4b48e884b98aa57c5a4853324bc8c3a391cfd7fd6fef124f874d37b9c7562b67b174962e734ca1aea0183844526b5120e9acd69c0a44c5b8ed2fe9e8b18" },
                { "km", "762fe6290951c8e8cd771e9b8364f274b2c6842771bd7635817a93efe36b2500ccb1464a8dad9970d686feccae2d220f5f5c6c743f74052e65e225a84eac188e" },
                { "kn", "611543a676f7a9efb0bfffc1dabeca24e93f763158d42ba8a079803d6ce535ac68348738bef4aaf991192030e6f8b14a85b0b4ff7708cb573e993257ff87c2cf" },
                { "ko", "25e2e0d403e5effcfed07197ecf7a3198708635bb3fd735e13bdb1dfeb3c7c244784e6893014e95ce2989a13ba5d54035d41b838cb457e6ba924fae6c0c36491" },
                { "lij", "75c56d7653bcb781c7219523572c451aae955fe6a5f6b0d57a85398e51b6e26b0efd06fb8c68077426ce4d03e791763d21cc47a166b1188e3da2081696781a48" },
                { "lt", "cab86c5ad1bc001e6ae86301be3cf16254810c97569bf63601954157beed8ed915c3e23edad0ee251210863d114231e733a4e5e593fc86ff5f7f8f8baee708dd" },
                { "lv", "409e1c50effc07950d86fbc4e43eea55cf23dcc27be20cd6ca1191f6b725819980322643b47489a6d0bf10c890501f18875d3abe8e6445751bc2a8b72f76004e" },
                { "mk", "23eec0b48e393521a7c191f12de5e9715389367851bea60b805ee8fbab49249c10f34ed376da4f279577c5bd4217a1db0bfc73128f5a3c71272836f4fbd52629" },
                { "mr", "35002bd22246516b2324bf0eb67cd258a7f2d4997c44a14db740db419fc7fa7a8bf386cc4493ca7e04b270d298eaf18d335a32cb8b076870066c10a6a984aabb" },
                { "ms", "25d8671453d84e2031cdfb9376b6647f4a96eae3a298d2d6b572263c27848bff8952954d46193e2aeeb6b91df3ef34d354696085117f1fcafde1a6f0ba51c7e5" },
                { "my", "7a9c8f3f1838094a07f7e94f4d2659b7a406efa0d93140aa997f34113fe5239ca5ccec023167421f734410b0eebcf0c7e8d844f61ed68556c70b493de1c4eeb6" },
                { "nb-NO", "f947a58ea1bb7160a581dcb56f9f791d3f72c40cdde4ead94baff18e5ef805e747873305f6c4e5f025c9c32206f2f1ebbf2bd8ccc24d680f4bf289718071159a" },
                { "ne-NP", "ab12ba6f3ae9b7df44542d7a362250c76c38206ad943d22fd9240cec098b577a333dc6140b675521a28360899a18e6ee412a6035452e72c96fe5a8382f430f30" },
                { "nl", "0f4319deb2b582d0bb899144ea1d1aa834f6ff9772a909d1c5e1fbddb260c6fe503294e4b7ec5428e04ce91c6cfe7e515d3abb09b081fed89d5a56877d15b1bb" },
                { "nn-NO", "d2f929ffa609b29fbf90f58e4519ddb6048ee9548d7d863f0cbb02dd221cfd691a7ec0ed7111d834e172c9cf7ee725c1a873d194f572fede908ff4f2722c62ff" },
                { "oc", "46fddb6db3c414d9fa50a4dd90c29853d98d220aa07f7a866bc8b5fb1de036cc5325a595d86d0be796935f2e2aeb9764cec3b25befd1d4503c28b0525b65bef4" },
                { "pa-IN", "a181525750661e6cbceb00dfe5932b5db9ace9c3ec7197eff430866bb1e669d9402099bc4a6e7c660631c76e938503ecafc8131dbd97102bea9ce42fb7b6658e" },
                { "pl", "ad8fe153adcec535daf972c8d4fd391beef5d8aa5972ac49912dce1ef942b4e6cd4749c7e694a8151a8b2bb90f31c0e66dce6bf65370724ebe96c65f9daff69c" },
                { "pt-BR", "bb389140d588710432caa8ddc2df156ef6cfa0fe9cf096ea7e16e4f2c405aa41b096ddfaa4efe0fcbac080f0b7c7e2045782446c09c54507de004a28f69e720d" },
                { "pt-PT", "18892743f79799683c6d2af529aaaed0c8ebcf55736e65d1de34467eeed6cd83ee6baa6b0f13d2f6c15fee87cea94c22c4cc7946d1f510b4532cdef563cfbfcc" },
                { "rm", "c4d1fde36b1f96c4a73d675002313d1bd3bff2a796c1be695f700960922f30c8f8f82c5bd530113e139162b944b3dea9b75bf0fab8e6508f6076021a4d795582" },
                { "ro", "c1f387f7a7172f4f57135e625d094cb91fba70b851e2e754ffc2685f8ee74546c3c4e12f980ca928cbb793d17776348867e3f2d14461557597964700a9d1f000" },
                { "ru", "eb3cb97f2f24bdc77dccb51d288553596c7c3b215b6f6d3486bcd805e8acc77fedff9a30aa4c475b57d4f01165a6e8370e5e0a05929de2b10af1ccbe6d2046b7" },
                { "sat", "072d0743d30c2a698c5a99b1575f2c8a3551a15caca1d69718345d65e93753c07e00be5f08f1d7f8e36df84e19d2a9d8543740c98af4d4c6b650b1bd5b9ef90d" },
                { "sc", "c132544a836a80fcb1ff46599e7f733e31bd3ae726f2538b77e988e1ead0cef19019de86f1fd0f138cc36003a3c8ec5eb450db1c4ac288e2244b5b45fc96c6c7" },
                { "sco", "00c32b181ef22c33a6f3af7d9091ae36df60e39345530672e4012517172530b298b1e1193255e689a18b843c72c2a032d2fd5d135c8e230de75ac225630d808e" },
                { "si", "13348fbfd95224dfe65175c8ecb8d4b37c02712290838c66758c905282338ade2503a2eda423a629ab27b981d784c93c8879504c23c7be81528138aab3c9099b" },
                { "sk", "79ef19944d9828ae10f9669fd2598a817481cb2ab687748d88921aee997ee9c6503a3a3e315c23c02ac2bce0a6a2cdf24a6f20312d7c08d5792ffe08f9352c1f" },
                { "skr", "e1df12e34435aed9b289eb6a30cee51ea511d73bcafc586626c1221b52ec55130a6afed51e1109cd99b6abd6dce4501058a337195c76066e4d1efb0ba5770992" },
                { "sl", "4a4f962d086c3a7f1e6ad252090c56f328d5a40c5096dd010e68d4e224969d332b0d158b98acc8048421586e9f3a0d963fc90902d1b6476433ddcbdeaa850e1b" },
                { "son", "e446c7b9013090b48493431fe483dbf2b7e78b12514e4083b4099107dae49bb8588e2e061f8c0e5bcc546e2f3fb08095b9ccfce3339093e5fbfde4afff6872a9" },
                { "sq", "8d26d3075acf46db52242254b755bdd65b09c0aaeef14f9cf9a8717e9400a4c3e7b10bdadb9468c7debfeec3d152628c772c6a767e50fc7a83b2b1d09cfa33f9" },
                { "sr", "6363d6f9b0fdf9d5f27dcab6b7d54caee9b480a3e7d1233ec1615505df8370a8aefe6bf8635b1127afea529cc1a184ab42dc7c878871c9913adbaadfd83f70ca" },
                { "sv-SE", "2bc2a4462133673399e2e1fc605013803f0296ef0807fe926e2963721dce42fe2a57c37032a9c5712f132c07edc5e1d76758a24b74ea1cec3dedbbb370a69e30" },
                { "szl", "c92fbce9e06759dc1ff1952b9bd0d5a6a125d2feffd401249fd8e64531a08ccedc88a8980f37d8af349e0cca7862eca47c3a335420066eba5e60a70bc4525aaf" },
                { "ta", "e90f902516445fe91ce2852ea33e5d4d6a24c92093033e8c6de75bc78cacccbc2fde088645f9a70331258d6cc7d4349682291420cece1fc04a1312fc1cbe2829" },
                { "te", "55353e18c5237a61b97c3cebc7733a4cb4c4da80c287eea451e6f3e7026585b30785de47ddff9a89ff7b243ee4c6ea66d6e1ff411751a25b8e6ff999ebb47069" },
                { "tg", "1c9f50cd5e261cc44495000f689db383446035ca98f2094fe86847ba545b6df4b309cd2592431de15c50f92a72f94fd4b9361dcba38c697b53af2413cfc12f3a" },
                { "th", "41913333a56818248b55bf46d045b03fc9035d3cff701d46712f8faa3b69d73c3d1d49d8bccfbd086c2a10833a0caab23a5d7856a48b954a22c101453e77b4e3" },
                { "tl", "cd8a3654c577128e9ca0a82fe73ba6180d1371364e242869e03e847213f5aec2d19767e62c3325e64ff6d7413150f17ddd5165f4fd11e2e85065a3fc72df41b0" },
                { "tr", "e2ffc24a7561f085a5e9c1ece3521dd0526b60be29e41a08ce49ed8721c5802b25382d737a1ca96d97a5795a49224ae67ba1f7ea215dba9a23390dc701e41848" },
                { "trs", "40f4fdb8d05222941b40c30407c0bf80bdd595a06bffacaaa5c21bad39121811e7a334f75b23ebe55e20bb166473d6100ce4b8a39c66c50672284a5289576057" },
                { "uk", "7ee00eda556c0d367b3acedd0d0e08ae187269db6a0a60ad2b309c5f403767441413177ddbf7f619e2bb498fe769ed18a8cb5008937cb6a26fd2fe178ce0b9d9" },
                { "ur", "63ef4cd92595e45a316888a35e597f177a778272ab25f6ca791d23332437777f14765803aeee6d221585839bdf33fb5aab8f63fb5271286fbf4f4a07a7b4433d" },
                { "uz", "372b1e953cc344307dc1f61a43bdacd2628cd4b57b4af5753c4e1290a0e0c548d0545ccf0cfa2243fcbcb18a4074688bf50d6e9c5a6fc9715b6475848f91a482" },
                { "vi", "e5c1289d972a823a0fd395afd17f75f85b2e271f9a906acb78d26988790773c56f8da5f002e118851317b057ec78453332c1cd95cdc490c6b63ad45dada691b8" },
                { "xh", "d2c595abe79e3333557755c7b7f6b2d5ec7893008a6fe72262580c4b08a0c8f84a3101224eea863de1aa67b2e983bf96a2071437beb3bc919a2cc95dc9dac787" },
                { "zh-CN", "66a0c46601325b73dc721e8b91404cc4f2de5f9955ceb09040f20d8866ca2d1cda9a8372285d00aa3734bac28eb2491baf793ded271a56c6649a13dd84a4f385" },
                { "zh-TW", "2c73ae5731e72baab9e04c48a32c26cd830edbd51274f95e039eff334cb1f16a165b3acb26e7e1d75d391db9b96a45ec250f7599cc76adba826066f65ef6c4cd" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/136.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d0a51dfe29579690f730c205b66a3f03a44e8ac2850c4af3b50100d3a5eafcc6097557e4b9279e3bd8db27ea90dcf75d47fcb6b0b5fd6ea3ed1afd86e95d0e6c" },
                { "af", "19f3606a5dbca3a41391f0f4371fb0a00c523d5365e091a32b4ed6645b0256b5b603096884d8721c6d6a1f60b1d4657634323ef11464a40de5a4e07ef8b5ddaa" },
                { "an", "0c4b2c365b886480f69e12e824aebf22908a89e1f760ef153a1473383c13b36b1676aa942cbef6d045484ef593c23753389acd98d7372bb313c5ab09594fa33b" },
                { "ar", "f4a2af99e467ef7288e1397019b5e405684182684832a6d7e14495de7f2d6a7febc09d1b4f869688ddd9ab7461789768ca04c3a6b1498a8e92f3783806185def" },
                { "ast", "84fb3637889ec693718d9175f2be8d60062bbb5e2046fe49e90681cbbf40f859dee5994425277bd827aac2d4899aa5ed43ad67eb31388321a5c3405d758afb5a" },
                { "az", "740578f812bebb8fd537b724c092a66092a3d075122758395de9124b11626f053b3ddcb86d9bf2b4e0b3f5a9b9be2898853e37644700af037b519e646ec2c077" },
                { "be", "53e7fd9c4497bad23de6d23963a24f7ce1e1109b8d9f5e09593472c857238df0f2645dba783abce6c642484742a39d658c0fd5e9de21b037c90ccd58c3db5927" },
                { "bg", "c769fbfcf10430d3c116dd3af6cfd67b14b30557513fb63e12c30bbb47603d1ed40fee40a64148ecc13799d605ba21468bf5b620093920216895f5fa1d55e865" },
                { "bn", "6d2357b4b1846dd45a8c378ae3004cbae3deb51c044e5aec9b9d05cb2e9880a47c284e41cfad74bd70c33a5ff9cdee9a0f3443b28fbbfb27f6f8d7463ebb458a" },
                { "br", "387f26948318556a47494fe900f9dc1b340735c827a6f2d30cb933ac5adf3944dc563bb719317203423dbf39fbcf061d06c213f880aa9bc821bdd12edf2f15ed" },
                { "bs", "dc02b69214fa5b6cdda6fe4e7e3d24468bc4d8e793f05b91047a6129a31011cb5258d70c2e9e4a449589af597d9b589e4cda637fdf83c4a892ee8599707378ee" },
                { "ca", "183161e37054ecb8a324bbe8b4bbb6710dc8a38eb51e972f8cdf8e6f37a418f48cc18d65399b060ee98cf2c2300ddd544d2588e24425f2c7f65ea4e567e8852a" },
                { "cak", "7b17e7823dc802bc91cdb515b6dbf614b53ed48022e182116298fe96b4913ebf23fc0a78fe3a1e1336f209b93bdba3fcc25997b60c6f02f594546859ed9ed61a" },
                { "cs", "29dbc24a210f812030f282206c20f54dfaf48093533d35bbcffe1e8d31bc6cb6dda1e89617c3655ba923bed2252dc5bec294e66b35b3c650b356c151326518a4" },
                { "cy", "ac5fc8f4ba8f09956c92e84920b21844a30f5acf426997a980da180c2e1dac8938ca880da9d91629aecc9247d3964ec3b446b4f6827dc7756790ab2c7d322435" },
                { "da", "9f2061dc00f27826b2051a966a71294f59869dbf5addbc0c053af8ad2fba6d812140453e619955d4fce671a06d6628fc226dd7899eac723687195d507e38d7dd" },
                { "de", "c58ff7a3d320a447aafe8842119e2ee2af2ff443db0549db2682dee5280c4f88ccda1ae9b70ccbacd1e4eae94afe60f579cfff38d9ed22aff97e5c40c35898ae" },
                { "dsb", "22f694b7c573230615e3676d0a7e5b849b4884f5dca72e501b410ab36cf1a2f8cc3f5f78aee71e30296bff8e47845141bd555f27e10591dfde96720b972994b0" },
                { "el", "cc9351d4717ce49808d973a3e70c61d3d2035fe24375a0d63656b193acbd66c3bd374ca2a8f876f2c25571d73b31f971e43327450d5b8ac91b626329ae198b8f" },
                { "en-CA", "56f5a86b1ce2cc5eeb0ad42e89a37bb610c8537965ec5b1cdbab5008aa0a5b61fbd67fb7f82759da65e899ce5fcb8d1dbb3f6a3c231c64693436c64b21e54d25" },
                { "en-GB", "169f7523b05c9694491515c9fd3f91564d6e722a1bdea59dffedf243986d3b6672005a23b3018cdcccdb2fc8e2ab04af862e015d41b51df400407d4348964a76" },
                { "en-US", "0b5aa45b5ec42277e2d5ff2fa1beb899f21e75df4d5cc3c62dfc58bdc0a3076749ecda5c8a1df6e4f010da579c9a6c543f49494314bd43e315d3f0898c5eda35" },
                { "eo", "52d6bc4b4535439a640325e13ce10e0eb820b4afe95a752b19724fe9d8fdd682b539e4544763a7caaa0eacafe735d6f853e48749211a43ece0cdf98f4a5fa686" },
                { "es-AR", "be5b59215060907fc4873c96f0648a6b406df496bcfacff705e6d8c754a0eade42ad9a63c09a979f6e36e52d5484968be2e26673ef84a29c343a9e600ddb2a82" },
                { "es-CL", "69285454855c0e39b3978c91c2cea81e3543b734285bd18a89171152b3fa5cbe3093a7fca9ac50037480f986df628d4fb6d70f0ea5632155c4c245abe1fac3e5" },
                { "es-ES", "d9196267c43720ca4901ad4404de86d218c4c85617792bd13ead6a878f558789dfaa92f4fdc8a38d543a78309b6252391b2ec09d4e594584da5a12a1a7dfa852" },
                { "es-MX", "0f34427dd0d7cc81027a25fc94b481bc74037d8b954898777f6807423e37849f8d180074eb9a77295be8ddc921bf7a4d28aec28cad07f8f8cdda5c0d9b58dc5d" },
                { "et", "aae7741c905c984952684c12275ca1ac81b4df3167e7e489f37976d8e7dccaa73478bba7cca856007bcc74760526ef6a040d9d38f15911e546e7f93fab55ec60" },
                { "eu", "18aaed5ab71c64b1131413c39039a2750976c6ee354ddd59aa3546006e6647ccb4f89e0f9ec187bef1ec0ce9cf86d77368963fce6e0ac7503d1081e50086f01c" },
                { "fa", "bd53074241b18850a5999991060d9583af42df0b77534675ce031cc6b19bc7a55ef73ebf9cd35e01774003f6de9ab0248836a38c00e7cd585e9bd19e6f91f551" },
                { "ff", "6530bcb307864099c76f59081ca2bb46c76b1fa86cfcd124e5492cee9d6a3281aa65d7be0bc102b3fc622165ee7acfeb55d48a9ef6aa7c212733b21b78f72827" },
                { "fi", "02ab2f46f130fac40951345728eb109de50f7778d8f09eee7796f19b8df57d6bba0d6c29b4a5b812970488c40463ead279aec333e7daa8a425210ee179151738" },
                { "fr", "aed4e5008a6413a6e535ee31c7c2ed8169dd3e9460d85f7d21b31b42f9138e129fe11deb134285aa2e529c7128f39dd89e82d346dfefc508d40b18b8a996f3be" },
                { "fur", "3be24f33e5aa9986612f4e22b22ffbfc259fd522ed9ffdd0c207b55d488345f24e779a0f70be1d2091a4c204b10a415652e8f29cd94e3288941de6c3087ac558" },
                { "fy-NL", "be852df3813f78c9d675267b0bc63e5e6632af3b232041267adadc9abdde31a2b7a93379efcbc275a72729cbfe3128c1d190d7eaa75625f141ce8072cd1f51a6" },
                { "ga-IE", "cb8c0c7f82de9eaf366b6ed12c183e26e16a13555138d1b49afc72cbfe0de2aecdbc3546a71d86d971459bd0c3bee010b24c10a759c896a58871e3d425d3cdac" },
                { "gd", "8c2083fc70a7a12c2813b041dabbb5f223d42b8f6ac1909d646b368cdfeba5fb8d9befb3034281d689f48557374a1cc3e170538dfc08c34ce74436096c35d709" },
                { "gl", "a9750a9d69f8b5438a7f6feb280982a41097c0af49ce37d583e01c01847630a51296a047945228b8e99fb556c34e9eb566702fad3dd7df371d3776cc69925724" },
                { "gn", "2f2cae0715f68e433df3fe73eeb7aefc1eb485ec0524f04e7246ddafd3cf7249159fc5d91b8c12616b79e615c52bfffbd8206f2da91bf68419b4517cb859ae82" },
                { "gu-IN", "f79f48fa83964c35882f669dae5a9046075dacff57a7fc1420e17007763095dc7da7f094c8988ead8dada50f8f786288c134b280eb176de63792ce3cb60ed3e6" },
                { "he", "450e9cb963c54f6c24e6724efc714ccda8a3ce3058a04c6b518f6228cd0a12c012aa9cea889dd2980df4993f5659a836b9b45fbb852640f998361d830b475df3" },
                { "hi-IN", "cc0da8035a4a39f2da83c8c5050663f9389e622c09043a87da2bb29ba4f139bc2c74272c8d4b09600c2232baa301eff286c1c917ca68da746da600f6c3ec15a6" },
                { "hr", "b7d6da01f9af39c68e43b684ec5ff32174545b052af5a91b585aabe499e048c3b15ec26bf6140c482962959aaec1b2ec610c76d5787c19fc08792b4563aa150f" },
                { "hsb", "3ee422a284fc4fc3516f0e877738542bb0cbb4e21946cfd4aa59b9e8102f9ea56b27514b7c3333aab91ebe9d355aa663987344b5e738850f0e10117c2563e122" },
                { "hu", "06a1b97e0ef7c5de28700f33e7ae54d4c4f34482b65defd7360f5297c48b193a60ea5cf8ee701fed2d3c1fa4bef3d9304c9b17f94f8d3332688b21b8c2e497bc" },
                { "hy-AM", "58a686445f7274ceb9d3c002b8dd0827859bfc31a6942323aa9575418e0b8fd1ae8118c31764be86c0c1b8f4ca659c78dcd9f1664b95cf0dc2ba9695423cacd1" },
                { "ia", "7d6acbb572ef6cb693950391e9fa25b20454e54d8f8be84574438f496204814e7340dc800801b2a1afac178a19b1e022e1052d1fdbfe341d69bbc7b90c064ddf" },
                { "id", "45aec277835afe6a612b56bf72a6b83e445e8f0cf2375c67f142429a7daeb148cc2d9a20f0fab9160dac1835f7f0899a122e2ccb299b5247a281707e61534b26" },
                { "is", "39593eb6d19e1f21b6b5f85e54fe738a9769a0c23905c5f5c0aa14dd953af10295b470bc708678c197eb2e4513dd459d4be2b3ccd9b7aed08e5211257dcb989c" },
                { "it", "692cde1f612c51127bac6c89b59735e3397a234b14323d0bfe6893bd46cfb84fb84023e5b86da12ab6d88d31b2add66abc65fc1fb4184e7f338f1a1c27d0246c" },
                { "ja", "1cb6e82f04363cc4694effe76a5d5e98b6af06e40b6d12e3a9a5c02b15271f39e9a8461d28785fef455e9779294ec45f0f379cbb90cb2ce4c08af200be57e74f" },
                { "ka", "26877b6373c4db337e77cbae09f0842daf35aea902a8dafee3b515a76e771d8209aae8e1a2cf7ef8e3ad0dff2ce58da471229b205e170c52758b332d6983ce9d" },
                { "kab", "258a3442a76ad9f40ac9323eb7a4f87152d78aca9b02ddcb77422de1b6f674dd8183e4fc08b3d8865c66bb5e682b972629ec448e37fde75d0b21c35a5ce85f25" },
                { "kk", "d81b80b94cbe4f94c373963a3e3a095f14e6323bcbba59def05c0a6b61484124b7f9d8d2fb73fedda6da062f4a51b4b07d85077d0403923fa77a150d469fd9d7" },
                { "km", "96f6164f263871d338f25e54dc54e00078ed74f42d06d036695ab9f1cc9cf43c754fc8cd54d2e1f09a9b49b146fdc1e8ede21d9e6118b1807d77b989a9f9cd09" },
                { "kn", "0bdd7ba42c06455f6fbac91b057f05f2151d5aac83685240f2628df35cdd128496f8cd356133e038f8373c85857dd166dbe1ac4062b60a70bce866076bc2f00e" },
                { "ko", "b617ac1ee41e91cd0f13dc0d1a53fd7f62d5ab70450a030134c1ee4538a76255574156e220fefca904c556b47a679de56d73b065c3fbe51c90b7ed20b9e17f4f" },
                { "lij", "0702425e48da1b27bbf9216bdee54670742328c4013bf542e88a04f176ff58a32018d8a7f5fd91d06baa45af17ee874132e15287bda15625063d04151fc6b463" },
                { "lt", "a0281872dfbbd4ac7417919ed97a221420c09bb2de090ba6212b57620b9cef0741fcf22ab98fdbec00a0494d79cee55ce969e267cd1a10beb20f710e4aa70bba" },
                { "lv", "a28e76dc261062d2106f8f5c4ba0ade737646696ee11f13f0b479980b637ba6edcb225f1452931066f2bd6392353ae9e1f99d10da7c7f27f1b6f915d3a52499d" },
                { "mk", "e51c53fcce7f6d1fc4a6964d5cfb2a4b9d67586f05200d4b6dabe85daf330d0b623cb20a6e156171ff5350ae2cc5af8eb9d11bdcd80c3841ad745452f48f1a17" },
                { "mr", "51f631e418de45437b08ec55f21badbda556a65fa927440bd4796352602b7d053a0e69bf96e9b2529ddc0d3a7ee5aa90cfff884d55e9ec96dea86945a34ecc6f" },
                { "ms", "e00079e5b4df83f0bfe219550978afab89433e35e285808495c7f1111ea3d210c4377b0e0f0d2f135e310daad0e5389010932d5814d872d2dfca9600f89c290e" },
                { "my", "328c28d5c13b90632753bdd78b731d30243e1bcee48e53db7ef8944e8c86064a709df5fe37718fe56565e67c56c9aa19b30ae950b12a4fe37a353e6d50cae0c8" },
                { "nb-NO", "84ff8b3d40efce1b6e75e727352d70c80124a4748eba96f89932f74c8e26c74f1e5aadbfa58d7dcf72a4ba9795404a807fb11ff93153559635b696d8ce9b5cc7" },
                { "ne-NP", "e71e1be8d42fb87688a85216bae7e1b5999ed67761e9bf49812bf03e99ea1582c96feed745e7cf7403433dac95f108051df32e250fe26038936832edee4bf8a8" },
                { "nl", "fa537e91e55a62940337be419cbcbb01fd1efe40d917ece56ddf206e345a10be275f71813bf71d67f322fdbe0762c41e29e7d09df9172173785a080791df3f84" },
                { "nn-NO", "04a4245c4582cdbab323c17a28243c30fb539f98020b94ffefbdf88286c1a6813789c7329f21bf22c499f292179498adb6b16e694a5513ffb3b4bd8c0f697a18" },
                { "oc", "b4ca23084142b8b71557d47418926938fa7e5d25ae3f6217bbfea33b80805bec956de69d1115355e16837429cd6a8030da10420a390415d2bd8a452b8c59aad7" },
                { "pa-IN", "a3a22b306b8ac2789e3b7d72c060335775e4204633ad3f2c57b08762ceaafd2b049def817800519abd21f054e518da46f5539cf3f5ecba882eb2dd00502ad262" },
                { "pl", "d9d23401f3460fb2567e037a8c2b98714d8312b64ff90f734c0bf5490b15030a1e97f071331cef31b60043d2e4bfa9774debe8910c08ce8038448767f45717d0" },
                { "pt-BR", "a295e4d33793af9ae6409311b587e5af247e72d250a7beec08d8ab7d077898f03f0bdf8b562a1c914586e2fca07bb89efdf2c43b501a5317e189319447375fa3" },
                { "pt-PT", "b7b3e62b84dedd62b04849f5cc6d05e63d7d01694e92880b5ba9c742b559a5978c63b70bb556580aeccc39237508ff62fa9a426e01c34933e6ebc523f95cbb29" },
                { "rm", "4ffdbe70ad1242207debe168e00e7891ac90bd52918859bd55b2c47f012b3fdc4098029aaddf3a9623ae986414ab17d816f683efa5634df8b9c495ddb75a4b44" },
                { "ro", "f29b8282a789aad642a9d99de4d7470caed563158c965cb970890576f6bfdecf72abe66b69be62c8e8400781cfbccb77e1d597589841e8e3b52f61b85275c381" },
                { "ru", "bf9fb51b52541b0e2f0de987b5d9a30e6c6dddcd0216cd3e9121bd1c90ccf463af5642e43a07caa6a313e79984b8fbc6500a82f75e1c6dca57b793110f238886" },
                { "sat", "6539dedb2aaf64005b0f9e698773c39de7905d22bf9535baae93b8fa00f6d46fb20c88dd040c539669042ca0c113b3a67a45ecd0492f1eaf62f9b9a088ded26d" },
                { "sc", "1ca91e7d5fe2a3657424e4c726756f1f55667b71017433a2101d862c73316c6afd40dcab3e56a67aa14e3f647064ece8b8d483e3f028d03307a151975efbf6a4" },
                { "sco", "d1657f8690ba9544eae6b9ad384a8e749db5f9006c93cb9cf9ba775802fe7b0a4e46f39176d0ccf35c7ab4a20779ac9113b6ce2f9be6e776782a05a2cc56c4eb" },
                { "si", "f783a7942d8f3267e5c3dbeceeb5e848efaab7483ac7524e04e1c19118d12356e748adc12b0c1f53a41d18d8ed9fb0e60247c85943cf841f93a19f91e17c9c9c" },
                { "sk", "39ac4ec3d5c3be0b354b21972903927e4c07df45cb3297f829008bfced7cf51b36b60c26ffc9a5f7bb5701ffb25d5b3c60b78bfe635b9645797500a414bd5264" },
                { "skr", "1a8427b5ab8abf5af43c90a7ab8f01a20242cbc7d98c105f2e8b4b761f10a111b3588ac54eb20b04983bc4bc7f5b9078f436a0e036f1fd4e7774ce03b714d7f2" },
                { "sl", "f4abf2fe01e4e7a296bf3a8698b9cd51f3b86599cf6dbacdb04904800928a7c20d819bd2f98b47729b6243d37b1af49fae8a03aad9d4d319b7b21f7abb9f30d9" },
                { "son", "dcc47634ca2c5b64b636aca18628cada93ac6f6bf0223fe08c62a86b0c024681505f4bab5c30a38ce2d385d50e0dc1281a1add2881d50c1b94759224dae2167e" },
                { "sq", "4a91f3182cf63a17e2e52de5745309cd02a6d69fd8199ddfb45ac189eac80809d2fe635b78c7f6beaf6f0f6e31187dbfc6cf61c600433f5a83094aa42ebd68d2" },
                { "sr", "2bf40a9495271fc341756089242b8e5d1ef0c0d3c7c2b475eb53ef63b5c53c3a036e50b3194415101bd279c507145337e1549b4dba151b9fca989d14b3aa162a" },
                { "sv-SE", "0a7a0a326cbf1d666ee3bcdba7fbf305519583b097bfe702380b38ab9030dab8777168611b5a0617138be0dded457656a3f6e48b5f13398430cdf639ff9ef0af" },
                { "szl", "f23c78238204d829fab5b596ae11448101c2869db31cb30d73074a497791d19e3e827c5039faf1f8029b095485e0298a53977211c56bf627545a36d110ffcf19" },
                { "ta", "ec8645bdaa13787053c9fef26f4c15c6a872615e3ac537b25f0306b7f6b00ac0e84343599dad691cc949d900f19f27683e5469c6925bc2e78b279654c737b30a" },
                { "te", "a97ea453cf64f6dec37ff15eaeb3b7b748643f935a1ea21e1106f7948d2ec4fca5339c1ffc4caaa9daee67b91ab5546dbdc665820e4dc8766e30356a62f708ac" },
                { "tg", "73e2b5352740c3be990de29c65ff049d76ae2422b9f7ffbca86199e800d787153410797b82f3552961a1cbb30ae3f91fc9298cec0c727434fed26e4c8492bc5c" },
                { "th", "060ddca75defb9571220e360fa24ad326730d2a8a67f68f950a1df073e9414c07df8b24eaf96d8d4fae5a29d54c83bf1222121be5db679ad0a194ee6a9428b6a" },
                { "tl", "bfd1aa8997c1452b43522c80b47881fdbb8c4a1464acc3abf365602c7345bf32e318e19e8584b65c301cbcd55a92b594f68e5f2048702bfada9038dc972e75a5" },
                { "tr", "0ffd2d6924cbf26ccddd372205483442c2fb6b926c92f6cc463bb2d2ffcb7cac84479adbda92e13ba6b0c9edfef19dff7749f3f0036f78c865a38bf44ab56e3b" },
                { "trs", "f2daa963b189a18d3258e83a51ea380f7043a4121ea84267a2e934dd67d713a50647882e043e5e2c2f1e69523ab84c3a526ea3c6cbd36b4a4afe6b89c893804c" },
                { "uk", "63c93da910b6e3d44d0444c9332f594fc08d22e574b306b00969727150eb7fb12d44f1a575fe45851952617451621c1c279f19c750558600a079ece507f3dfb8" },
                { "ur", "348a1e666034c2db15b46e541a451170e2f8f99b60fe9b05ab32b28db45ad3ff02f2c269de91369aebf41f93029360d398dde831507c2403ef463173188b456c" },
                { "uz", "59e850b8b09c2267ae6cce74e523865384bfb4c526c61bbdbb5f0ced478cb729500745edce555848bc8403ce5db53a7c96fd0f5dcba8a3a8689f3f64e76fdd58" },
                { "vi", "846ff456e9778444c13a10f3c15e493f012faa795c7691db50c9ff272f86ffa7dcf36e734f63ca3a77f4fd3f7b87be5fd29c8b49ab564c4d0f82f47a84ff33d8" },
                { "xh", "e5c854c90008a7ca0e98c55470ff91f1eab1a6501f512d02925bda688934d1468b2a3441e1d6f09ccf2ae66dc9333a2facc2bb98e0773a4c5439d22d053d967f" },
                { "zh-CN", "c22d3a824aaab6be7bf602ca9b5775595296f66606fa4c9d160e905b6e281aa8dd06acb7f7ddbd2b355aa1fb0c5450d568feca74ad1b4a4886d25b0fbe8cffd0" },
                { "zh-TW", "fce59dcd4323bb257869ff76b41b3594ea278974abf0be8cc6126bcd1d24d93ff86c510ab676733d413cdba3b40eb27353d8f1fa651e04d1afd656cdd12cdb25" }
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
